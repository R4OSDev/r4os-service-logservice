//! Complete caller-owned diagnostic snapshots. The SDK reader owns cursor,
//! restart, page and clock validation; LOGSVC owns allocation/publication.
const std = @import("std");
const r4os = @import("r4os");
const a = r4os.abi;
const inventory = r4os.inventory_reader;
pub fn collect(ctx: *const r4os.r4sys.Context, allocator: std.mem.Allocator) ?[]a.ProgramInstanceSnapshot {
    const actual = ctx.base.generation2 orelse return null;
    const provider = inventory.fromContext2(actual, .full) catch return null;
    var clock = inventory.PlatformClock.fromContext2(actual) catch return null;
    var now: r4os.time_contract.checked.ClockSample = .{};
    if (inventory.PlatformClock.sample(&clock, &now) != 0) return null;
    const deadline = r4os.time_contract.checked.DeadlineBudget.init(now, .{ .kind = a.timeout_kind_finite, .nanoseconds = 2_000_000_000 }) catch return null;
    var rows: []a.ProgramInstanceSnapshot = &.{};
    var transferred = false;
    defer if (!transferred) allocator.free(rows);
    var reader = inventory.Reader.initAbsolute(.full, .{}, 0, a.program_inventory_page_max, provider, deadline) catch return null;
    while (true) {
        const progress = reader.step(ctx.programShouldClose(), inventory.PlatformClock.sample, &clock) catch return null;
        switch (@as(inventory.Status, @enumFromInt(progress.status))) {
            .complete => {
                const complete = reader.fullView() catch return null;
                // No record is exposed before the complete generation agrees.
                const result = allocator.realloc(rows, complete.len) catch return null;
                transferred = true;
                return result;
            },
            .capacity => {
                const wanted = progress.total;
                if (wanted <= rows.len or progress.restarts >= 16) return null;
                const replacement = allocator.alloc(a.ProgramInstanceSnapshot, wanted) catch return null;
                allocator.free(rows);
                rows = replacement;
                const original_deadline = reader.deadline;
                const restarts = reader.restarts;
                reader = inventory.Reader.initAbsolute(.full, .{ .address = @intFromPtr(rows.ptr), .length = std.mem.sliceAsBytes(rows).len }, @intCast(rows.len), a.program_inventory_page_max, provider, original_deadline) catch return null;
                reader.restarts = restarts;
            },
            .restart => {
                if (progress.restarts >= 16) return null;
                _ = reader.restart() catch return null;
            },
            .would_block => ctx.sleepTicks(1),
            .initial, .more => {},
            else => return null,
        }
    }
}
