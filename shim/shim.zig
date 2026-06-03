//! curlfromcache / wgetfromcache — native shim, the Zig sibling of the Python
//! shims (see ../src/fromcache/_shim.py, the test oracle this must match).
//!
//! One busybox-style binary: it inspects argv[0] ("curl" or "wget") to decide
//! which real tool to wrap. With FROMCACHE_SERVER set it finds the URL, probes
//! the cache (using the same tool), and on a hit re-points only the URL at
//! <server>/b/<base64(origin)>/<basename> before exec'ing the real tool — so
//! all flags keep working and the saved file keeps the artifact's name. On a
//! miss / unset / unreachable it execs the real tool with argv untouched.

const std = @import("std");
const c = std.c;
const Io = std.Io;

const PROBE_TIMEOUT = "5";

const Tool = enum { curl, wget };
const Found = struct { index: usize, origin: []const u8, urleq: bool };

pub fn main(init: std.process.Init.Minimal) !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var threaded = Io.Threaded.init(std.heap.page_allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const vector = init.args.vector; // []const [*:0]const u8
    const arg0 = std.mem.span(vector[0]);
    const tool: Tool = if (std.mem.endsWith(u8, std.fs.path.basename(arg0), "wget")) .wget else .curl;
    const tool_name = @tagName(tool);
    const args = vector[1..];

    const real = (try findReal(a, io, tool_name)) orelse {
        std.debug.print(
            "{s}fromcache: no real {s} found on PATH (set $REAL_{s})\n",
            .{ tool_name, tool_name, tool_name },
        );
        std.process.exit(127);
    };

    var final = try a.dupe([*:0]const u8, args);

    if (envServer(a, tool_name)) |server| {
        if (findUrl(args)) |found| {
            const url = try blobUrl(a, cacheBase(server), found.origin);
            if (probe(a, io, tool, real, url) == .hit) {
                const token = if (found.urleq)
                    try std.fmt.allocPrintSentinel(a, "--url={s}", .{url}, 0)
                else
                    try a.dupeZ(u8, url);
                final[found.index] = token.ptr;
            }
        }
    }

    execReal(a, real, final);
}

// --- env (libc getenv; values live for the process lifetime) ---------------
fn getEnv(a: std.mem.Allocator, key: []const u8) ?[]const u8 {
    const kz = a.dupeZ(u8, key) catch return null;
    const v = c.getenv(kz.ptr) orelse return null;
    return std.mem.span(v);
}

fn upperAscii(a: std.mem.Allocator, s: []const u8) []const u8 {
    const out = a.alloc(u8, s.len) catch return s;
    for (s, 0..) |ch, i| out[i] = std.ascii.toUpper(ch);
    return out;
}

fn envServer(a: std.mem.Allocator, tool_name: []const u8) ?[]const u8 {
    const key = std.fmt.allocPrint(a, "{s}FROMCACHE_SERVER", .{upperAscii(a, tool_name)}) catch return null;
    return getEnv(a, key) orelse getEnv(a, "FROMCACHE_SERVER");
}

// --- url handling ----------------------------------------------------------
fn cacheBase(server: []const u8) []const u8 {
    var s = std.mem.trim(u8, server, " \t\r\n");
    while (s.len > 0 and s[s.len - 1] == '/') s = s[0 .. s.len - 1];
    return s;
}

fn isSchemeUrl(s: []const u8) bool {
    const p = std.mem.indexOf(u8, s, "://") orelse return false;
    if (p == 0 or !std.ascii.isAlphabetic(s[0])) return false;
    for (s[0..p]) |ch| {
        if (!(std.ascii.isAlphanumeric(ch) or ch == '+' or ch == '-' or ch == '.')) return false;
    }
    return true;
}

fn findUrl(args: []const [*:0]const u8) ?Found {
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const t = std.mem.span(args[i]);
        if (std.mem.eql(u8, t, "--")) {
            var k = i + 1;
            while (k < args.len) : (k += 1) {
                const u = std.mem.span(args[k]);
                if (isSchemeUrl(u)) return .{ .index = k, .origin = u, .urleq = false };
            }
            return null;
        }
        if (std.mem.eql(u8, t, "--url") and i + 1 < args.len)
            return .{ .index = i + 1, .origin = std.mem.span(args[i + 1]), .urleq = false };
        if (std.mem.startsWith(u8, t, "--url="))
            return .{ .index = i, .origin = t["--url=".len..], .urleq = true };
        if (isSchemeUrl(t)) return .{ .index = i, .origin = t, .urleq = false };
    }
    return null;
}

fn basename(origin: []const u8) []const u8 {
    var path = origin;
    if (std.mem.indexOfScalar(u8, path, '?')) |q| path = path[0..q];
    if (std.mem.indexOfScalar(u8, path, '#')) |h| path = path[0..h];
    const base = std.fs.path.basename(path);
    return if (base.len == 0) "download" else base;
}

fn blobUrl(a: std.mem.Allocator, base: []const u8, origin: []const u8) ![]const u8 {
    const enc = std.base64.url_safe_no_pad.Encoder;
    const tok = try a.alloc(u8, enc.calcSize(origin.len));
    _ = enc.encode(tok, origin);
    return std.fmt.allocPrint(a, "{s}/b/{s}/{s}", .{ base, tok, basename(origin) });
}

// --- probe (run the same tool: curl -I / wget --spider) --------------------
const ProbeResult = enum { hit, miss, unreachable_ };

fn probe(a: std.mem.Allocator, io: Io, tool: Tool, real: []const u8, url: []const u8) ProbeResult {
    const argv: []const []const u8 = switch (tool) {
        .curl => &.{ real, "-fsS", "-I", "-m", PROBE_TIMEOUT, "-o", "/dev/null", url },
        .wget => &.{ real, "--spider", "-q", "-T", PROBE_TIMEOUT, "-t", "1", url },
    };
    const res = std.process.run(a, io, .{ .argv = argv }) catch return .unreachable_;
    a.free(res.stdout);
    a.free(res.stderr);
    const miss_code: u8 = switch (tool) {
        .curl => 22,
        .wget => 8,
    };
    return switch (res.term) {
        .exited => |code| if (code == 0) .hit else if (code == miss_code) .miss else .unreachable_,
        else => .unreachable_,
    };
}

// --- find the real tool on PATH (skipping ourselves by inode) --------------
fn findReal(a: std.mem.Allocator, io: Io, tool_name: []const u8) !?[]const u8 {
    const okey = try std.fmt.allocPrint(a, "REAL_{s}", .{upperAscii(a, tool_name)});
    if (getEnv(a, okey)) |p| {
        if (isExec(a, p)) return p;
    }

    const self_stat = fileStat(io, "/proc/self/exe");

    const path = getEnv(a, "PATH") orelse return null;
    var it = std.mem.tokenizeScalar(u8, path, ':');
    while (it.next()) |dir| {
        if (dir.len == 0) continue;
        const cand = try std.fmt.allocPrint(a, "{s}/{s}", .{ dir, tool_name });
        if (!isExec(a, cand)) continue;
        if (self_stat) |ss| {
            if (cand.len > 0 and cand[0] == '/') {
                if (fileStat(io, cand)) |cs| {
                    if (cs.inode == ss.inode and cs.size == ss.size) continue; // that's us
                }
            }
        }
        return cand;
    }
    return null;
}

fn fileStat(io: Io, path: []const u8) ?Io.File.Stat {
    const f = Io.Dir.openFileAbsolute(io, path, .{}) catch return null;
    defer f.close(io);
    return f.stat(io) catch null;
}

fn isExec(a: std.mem.Allocator, path: []const u8) bool {
    const z = a.dupeZ(u8, path) catch return false;
    return c.access(z.ptr, c.X_OK) == 0;
}

// --- exec: become the real tool --------------------------------------------
fn execReal(a: std.mem.Allocator, real: []const u8, args: []const [*:0]const u8) noreturn {
    const realz = a.dupeZ(u8, real) catch std.process.exit(127);
    const argvz = a.allocSentinel(?[*:0]const u8, 1 + args.len, null) catch std.process.exit(127);
    argvz[0] = realz.ptr;
    for (args, 0..) |arg, i| argvz[1 + i] = arg;
    const envp: [*:null]const ?[*:0]const u8 = @ptrCast(c.environ);
    _ = c.execve(realz.ptr, argvz.ptr, envp);
    std.debug.print("fromcache shim: cannot exec {s}\n", .{real});
    std.process.exit(127);
}
