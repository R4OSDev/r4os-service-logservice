const r4os = @import("r4os");
const std = @import("std");

const service_name = r4os.abi.log_r4x_service_name;
const selftest_arg = "/SELFTEST";
const ping_arg = "/PING";
const file_log_path = "C:\\R4OS\\LOGS\\SYSTEM.LOG";
const source_slots: usize = r4os.abi.log_service_source_count + 1;

var service_payload: [r4os.abi.service_api_max_payload]u8 = .{0xA5} ** r4os.abi.service_api_max_payload;
var bootlog_buffer: [r4os.abi.boot_log_buffer_size]u8 = .{0xA5} ** r4os.abi.boot_log_buffer_size;
var file_log_buffer: [512]u8 = .{0xA5} ** 512;

const bootlog_snapshot_attempts: u8 = 4;
const inventory_restart_limit: u32 = 16;
const inventory_would_block_retry_limit: u32 = 64;

const StableBootlogTail = struct {
    next_total: u64,
    observed_total: u64,
    len: usize,
    dropped_prefix: bool,
};

const BootlogSnapshotResult = enum {
    stable,
    changed,
    unavailable,
};

const InventoryRecordBuilder = struct {
    text: [r4os.abi.log_service_text_bytes]u8 = .{0} ** r4os.abi.log_service_text_bytes,
    pos: usize = 0,
    complete: bool = true,

    fn add(self: *InventoryRecordBuilder, value: []const u8) void {
        if (!self.complete) return;
        self.complete = append(self.text[0..], &self.pos, value);
    }

    fn addDec(self: *InventoryRecordBuilder, value: u64) void {
        if (!self.complete) return;
        self.complete = appendDec(self.text[0..], &self.pos, value);
    }

    fn addSigned(self: *InventoryRecordBuilder, value: i32) void {
        if (!self.complete) return;
        self.complete = appendSigned(self.text[0..], &self.pos, value);
    }

    fn bytes(self: *const InventoryRecordBuilder) []const u8 {
        return self.text[0..self.pos];
    }
};

const LogState = struct {
    records: [r4os.abi.log_service_max_records]r4os.abi.LogServiceRecord = .{r4os.abi.LogServiceRecord{}} ** r4os.abi.log_service_max_records,
    write_index: usize = 0,
    count: usize = 0,
    next_sequence: u64 = 1,
    revision: u32 = 1,
    bootlog_loaded: bool = false,
    adapters_loaded: bool = false,
    file_adapter_checked: bool = false,
    last_adapter_refresh: u64 = 0,
    bootlog_bytes: u32 = 0,
    bootlog_records: u32 = 0,
    bootlog_next_total: u64 = 0,
    bootlog_discard_fragment: bool = false,
    app_records: u32 = 0,
    service_records: u32 = 0,
    console_records: u32 = 0,
    diagnostic_records: u32 = 0,
    file_records: u32 = 0,
    bad_ops: u32 = 0,
    requests: u64 = 0,
    writes: u64 = 0,
    exports: u64 = 0,
    dropped_records: u64 = 0,
    source_total: [source_slots]u32 = .{0} ** source_slots,
    source_dropped: [source_slots]u32 = .{0} ** source_slots,
    source_last_sequence: [source_slots]u64 = .{0} ** source_slots,
    last_error: [r4os.abi.log_service_error_bytes]u8 = .{0} ** r4os.abi.log_service_error_bytes,
};

pub fn r4_app_main(r4_app: *r4os.App) i32 {
    var ctx = r4_app.system();
    var dev = r4_app.devicesLowLevel();
    if (hasArg(ctx.argsRaw(), selftest_arg)) return runSelfTest(&ctx);
    if (hasArg(ctx.argsRaw(), ping_arg)) return runPing(&ctx);
    return runService(&ctx, if (dev) |*value| value else null);
}

fn runService(ctx: *const r4os.r4sys.Context, dev: ?*const r4os.r4dev.Context) i32 {
    if (!ctx.hasFn("service_call")) return r4os.abi.service_api_result_invalid;

    var info: r4os.abi.ServiceInfo = .{};
    var handle: u32 = 0;
    var waited: u32 = 0;
    while (waited < 100 and handle == 0) : (waited += 1) {
        const rc = ctx.serviceEndpointRegister(service_name, 0, &info);
        if (rc == r4os.abi.service_api_result_ok and info.handle != 0) {
            handle = info.handle;
            ctx.write("LOGSVC endpoint handle=");
            ctx.printU64(@intCast(handle));
            ctx.println("");
            break;
        }
        ctx.sleepTicks(1);
    }
    if (handle == 0) {
        ctx.println("LOGSVC endpoint registration failed");
        return r4os.abi.service_api_result_no_endpoint;
    }

    var state = LogState{};
    setLastError(&state, "ready");
    importBootlog(ctx, &state);
    refreshAdapters(ctx, dev, &state);

    // 0.56.19 (Pilot): blockierendes serviceEndpointWait statt
    // Poll+sleepTicks(1) - im Leerlauf schlaeft der Service auf der
    // Endpoint-WaitQueue statt 100x/s aufzuwachen. Timeout 200 Ticks
    // (~2 s) haelt programShouldClose reaktionsfaehig.
    while (!ctx.programShouldClose()) {
        const pending = ctx.serviceEndpointWait(handle, 200);
        if (pending < 0) {
            _ = ctx.serviceEndpointUnregister(handle);
            return pending;
        }
        // Runtime kernel output continues to enter the BootLog after LOGSVC
        // has started. Import that absolute tail before answering a reader so
        // LogCenter sees asynchronous driver/kernel diagnostics as records.
        refreshBootlog(ctx, &state);
        if (pending > 0) {
            const rc = handleRequest(ctx, dev, handle, &state);
            if (rc < 0) {
                _ = ctx.serviceEndpointUnregister(handle);
                return rc;
            }
        }
    }

    _ = ctx.serviceEndpointUnregister(handle);
    ctx.println("LOGSVC stopped cleanly");
    return 0;
}

fn importBootlog(ctx: *const r4os.r4sys.Context, state: *LogState) void {
    state.bootlog_next_total = 0;
    refreshBootlog(ctx, state);
}

fn refreshBootlog(ctx: *const r4os.r4sys.Context, state: *LogState) void {
    var tail: StableBootlogTail = undefined;
    switch (readStableBootlogTail(ctx, state.bootlog_next_total, &tail)) {
        .unavailable => {
            setLastError(state, "bootlog-unavailable");
            return;
        },
        .changed => {
            // A writer moved the chronological ring window between Info and
            // Read. Discard that copy and retry on the next service wake.
            setLastError(state, "bootlog-snapshot-busy");
            return;
        },
        .stable => {},
    }

    const was_loaded = state.bootlog_loaded;
    state.bootlog_loaded = true;
    if (tail.len == 0) {
        if (!was_loaded and tail.observed_total == 0) setLastError(state, "bootlog-empty");
        return;
    }

    // Only consume bytes through the final complete line ending. A kernel
    // write may be observed between individual putc calls; leaving the tail
    // cursor in front of that fragment makes the next stable snapshot reread
    // it together with its continuation.
    // Keep the parser flag local while records mutate LogState. This avoids
    // passing the whole state and an aliased pointer to one of its fields into
    // the same optimized call tree.
    var discard_fragment = state.bootlog_discard_fragment or tail.dropped_prefix;
    const consumed = importBootlogBytes(ctx, state, bootlog_buffer[0..tail.len], &discard_fragment);
    state.bootlog_discard_fragment = discard_fragment;
    addBootlogBytes(state, consumed);
    state.bootlog_next_total = tail.next_total + @as(u64, @intCast(consumed));
    setLastError(state, "ready");
}

fn readStableBootlogTail(ctx: *const r4os.r4sys.Context, previous_total: u64, out: *StableBootlogTail) BootlogSnapshotResult {
    var attempt: u8 = 0;
    while (attempt < bootlog_snapshot_attempts) : (attempt += 1) {
        const before = ctx.bootLogInfo() orelse return .unavailable;
        if (before.total_written <= previous_total) {
            out.* = .{
                .next_total = previous_total,
                .observed_total = before.total_written,
                .len = 0,
                .dropped_prefix = false,
            };
            return .stable;
        }

        const retained: u64 = @min(before.total_written, @as(u64, before.length));
        const oldest_total = before.total_written - retained;
        var next_total = previous_total;
        var dropped_prefix = false;
        if (next_total < oldest_total) {
            next_total = oldest_total;
            dropped_prefix = true;
        }

        const offset_total = next_total - oldest_total;
        const available_total = before.total_written - next_total;
        const wanted: usize = @min(@as(usize, @intCast(available_total)), bootlog_buffer.len);
        const got = ctx.bootLogRead(@intCast(offset_total), bootlog_buffer[0..wanted]);
        if (got < 0) return .unavailable;

        // bootLogRead uses the live chronological origin. Only accept its
        // copied bytes when the complete ring-window metadata stayed fixed.
        const after = ctx.bootLogInfo() orelse return .unavailable;
        if (!sameBootlogSnapshot(before, after)) continue;

        out.* = .{
            .next_total = next_total,
            .observed_total = before.total_written,
            .len = @min(@as(usize, @intCast(got)), wanted),
            .dropped_prefix = dropped_prefix,
        };
        return .stable;
    }
    return .changed;
}

fn sameBootlogSnapshot(a: r4os.abi.BootLogInfo, b: r4os.abi.BootLogInfo) bool {
    return a.capacity == b.capacity and
        a.length == b.length and
        a.flags == b.flags and
        a.total_written == b.total_written and
        a.dropped_bytes == b.dropped_bytes;
}

fn importBootlogBytes(ctx: *const r4os.r4sys.Context, state: *LogState, bytes: []const u8, discard_fragment: *bool) usize {
    const len = bytes.len;
    var start: usize = 0;
    var i: usize = 0;
    var consumed: usize = 0;
    if (discard_fragment.*) {
        while (i < len and bytes[i] != '\r' and bytes[i] != '\n') : (i += 1) {}
        // The beginning was overwritten, so none of this line can form a
        // truthful record. Consume it without rescanning forever, but keep
        // discarding subsequent continuations until their line ending arrives.
        if (i == len) return len;
        while (i < len and (bytes[i] == '\r' or bytes[i] == '\n')) : (i += 1) {}
        discard_fragment.* = false;
        start = i;
        consumed = i;
    }
    while (i < len) {
        while (i < len and bytes[i] != '\r' and bytes[i] != '\n') : (i += 1) {}
        if (i == len) break;
        if (i > start) importBootlogLine(ctx, state, bytes[start..i]);
        while (i < len and (bytes[i] == '\r' or bytes[i] == '\n')) : (i += 1) {}
        start = i;
        consumed = i;
    }
    return consumed;
}

fn addBootlogBytes(state: *LogState, count: usize) void {
    const room = 0xFFFF_FFFF - state.bootlog_bytes;
    state.bootlog_bytes += @intCast(@min(count, @as(usize, room)));
}

fn importBootlogLine(ctx: *const r4os.r4sys.Context, state: *LogState, line: []const u8) void {
    var source_id: u32 = r4os.abi.log_service_source_bootlog;
    var severity: u8 = r4os.abi.log_severity_info;
    var record_type: u8 = r4os.abi.log_record_type_event;
    var origin: []const u8 = "BOOTLOG";
    var text = line;

    if (startsWith(line, "[LOG1] ")) {
        if (valueAfter(line, "source=")) |source| {
            if (equals(source, "Driver")) {
                source_id = r4os.abi.log_service_source_driver;
                origin = "R4D";
            } else if (equals(source, "Protocol")) {
                source_id = r4os.abi.log_service_source_protocol;
                origin = "R4P";
            } else if (equals(source, "Diagnostic")) {
                source_id = r4os.abi.log_service_source_diagnostic;
                origin = valueAfter(line, "origin=") orelse "DIAGNOSTIC";
                record_type = r4os.abi.log_record_type_diagnostic_snapshot;
            }
        }
        if (valueAfter(line, "severity=")) |value| {
            severity = parseSeverity(value);
        }
        if (afterPattern(line, " text=")) |value| {
            text = value;
        }
    } else if (startsWith(line, "[USBHIDPOLL]")) {
        source_id = r4os.abi.log_service_source_diagnostic;
        origin = "USBHID";
        record_type = r4os.abi.log_record_type_diagnostic_snapshot;
    } else if (startsWith(line, "[USBHIDWRAP]")) {
        source_id = r4os.abi.log_service_source_diagnostic;
        origin = "XHCI";
        record_type = r4os.abi.log_record_type_diagnostic_snapshot;
    }

    addImportedBootlogRecords(ctx, state, source_id, severity, record_type, origin, text);
}

fn addImportedBootlogRecords(ctx: *const r4os.r4sys.Context, state: *LogState, source_id: u32, severity: u8, record_type: u8, origin: []const u8, text: []const u8) void {
    // A LogCenter record reserves one byte for NUL. Split long kernel lines
    // instead of silently losing their tail (the 0.59.2 USB snapshots are
    // intentionally wider than one record).
    const chunk_bytes = r4os.abi.log_service_text_bytes - 1;
    if (text.len == 0) {
        addRecordEx(ctx, state, source_id, severity, record_type, origin, "", r4os.abi.log_service_record_flag_imported);
        state.bootlog_records +%= 1;
        return;
    }

    var offset: usize = 0;
    while (offset < text.len) {
        const end = @min(text.len, offset + chunk_bytes);
        addRecordEx(ctx, state, source_id, severity, record_type, origin, text[offset..end], r4os.abi.log_service_record_flag_imported);
        state.bootlog_records +%= 1;
        offset = end;
    }
}

fn refreshAdapters(ctx: *const r4os.r4sys.Context, dev: ?*const r4os.r4dev.Context, state: *LogState) void {
    const now = ctx.ticks();
    if (state.adapters_loaded and now >= state.last_adapter_refresh and now - state.last_adapter_refresh < 200) return;
    state.adapters_loaded = true;
    state.last_adapter_refresh = now;
    refreshServiceSnapshots(ctx, state);
    const inventory_snapshot_ok = addExecutionInventorySnapshot(ctx, dev, state);
    refreshConsoleSnapshots(ctx, state);
    refreshFileSource(ctx, state);
    if (inventory_snapshot_ok) {
        setLastError(state, "ready");
    } else {
        setLastError(state, "inventory-format-overflow");
    }
}

fn addExecutionInventorySnapshot(ctx: *const r4os.r4sys.Context, dev: ?*const r4os.r4dev.Context, state: *LogState) bool {
    const inventory = dev orelse return true;
    var summary: r4os.abi.ProgramInventorySummary = .{};
    if (inventory.executionInventorySummary(&summary) != r4os.abi.program_handle_ok) return true;

    var programs = InventoryRecordBuilder{};
    programs.add("active=");
    programs.addDec(summary.program_active);
    programs.add(" reserved=");
    programs.addDec(summary.program_reserved);
    programs.add(" done=");
    programs.addDec(summary.program_done);
    programs.add(" retiring=");
    programs.addDec(summary.program_retiring);

    var counts = InventoryRecordBuilder{};
    counts.add("completions=");
    counts.addDec(summary.completion_total);
    counts.add(" tasks=");
    counts.addDec(summary.task_total);
    counts.add(" threads=");
    counts.addDec(summary.thread_total);

    var peaks = InventoryRecordBuilder{};
    peaks.add("programs=");
    peaks.addDec(summary.program_peak);
    peaks.add(" tasks=");
    peaks.addDec(summary.task_peak);
    peaks.add(" threads=");
    peaks.addDec(summary.thread_peak);

    var failures = InventoryRecordBuilder{};
    failures.add("admission=");
    failures.addDec(summary.program_create_failures);
    failures.add("/");
    failures.addDec(summary.task_create_failures);
    failures.add("/");
    failures.addDec(summary.thread_create_failures);
    failures.add(" rollback=");
    failures.addDec(summary.rollback_failures);
    failures.add(" last_error=");
    failures.addSigned(summary.last_error);

    if (!programs.complete or !counts.complete or !peaks.complete or !failures.complete) {
        return false;
    }
    addRecordEx(ctx, state, r4os.abi.log_service_source_diagnostic, r4os.abi.log_severity_info, r4os.abi.log_record_type_status_snapshot, "R4DEV.PROGRAMS", programs.bytes(), 0);
    addRecordEx(ctx, state, r4os.abi.log_service_source_diagnostic, r4os.abi.log_severity_info, r4os.abi.log_record_type_status_snapshot, "R4DEV.COUNTS", counts.bytes(), 0);
    addRecordEx(ctx, state, r4os.abi.log_service_source_diagnostic, r4os.abi.log_severity_info, r4os.abi.log_record_type_status_snapshot, "R4DEV.PEAKS", peaks.bytes(), 0);
    addRecordEx(ctx, state, r4os.abi.log_service_source_diagnostic, r4os.abi.log_severity_info, r4os.abi.log_record_type_status_snapshot, "R4DEV.FAILURES", failures.bytes(), 0);
    return true;
}

fn refreshServiceSnapshots(ctx: *const r4os.r4sys.Context, state: *LogState) void {
    var index: u32 = 0;
    while (index < 32) : (index += 1) {
        var detail = r4os.abi.ServiceDetail{};
        const rc = ctx.serviceDetail(index, &detail);
        if (rc <= 0) break;
        addServiceDetailSnapshot(ctx, state, &detail);
    }
    addTimeServiceSnapshot(ctx, state);
    addAudioServiceSnapshot(ctx, state);
}

fn addServiceDetailSnapshot(ctx: *const r4os.r4sys.Context, state: *LogState, detail: *const r4os.abi.ServiceDetail) void {
    const name = spanZ(detail.info.name[0..]);
    var text: [r4os.abi.log_service_text_bytes]u8 = .{0} ** r4os.abi.log_service_text_bytes;
    var pos: usize = 0;
    _ = append(&text, &pos, "state=");
    _ = append(&text, &pos, serviceStateName(detail.info.state));
    _ = append(&text, &pos, " start=");
    _ = append(&text, &pos, serviceStartName(detail.info.start_mode));
    _ = append(&text, &pos, " instance=");
    _ = appendDec(&text, &pos, detail.info.instance_id);
    _ = append(&text, &pos, " requests=");
    _ = appendDec(&text, &pos, detail.info.requests);
    _ = append(&text, &pos, " responses=");
    _ = appendDec(&text, &pos, detail.info.responses);
    _ = append(&text, &pos, " drops=");
    _ = appendDec(&text, &pos, detail.info.drops);
    const last_error = spanZ(detail.info.last_error[0..]);
    if (last_error.len > 0) {
        _ = append(&text, &pos, " last_error=");
        _ = append(&text, &pos, last_error);
    }
    addRecordEx(ctx, state, r4os.abi.log_service_source_service, severityForService(detail.info.state), r4os.abi.log_record_type_status_snapshot, if (name.len == 0) "SERVICE" else name, text[0..pos], 0);
}

fn addTimeServiceSnapshot(ctx: *const r4os.r4sys.Context, state: *LogState) void {
    var status = r4os.abi.TimeServiceStatus{};
    if (ctx.timeServiceStatus(&status) != r4os.abi.service_api_result_ok) return;

    var text: [r4os.abi.log_service_text_bytes]u8 = .{0} ** r4os.abi.log_service_text_bytes;
    var pos: usize = 0;
    _ = append(&text, &pos, "time-service zone=");
    const zone = spanZ(status.timezone_id[0..]);
    _ = append(&text, &pos, if (zone.len == 0) "UTC" else zone);
    _ = append(&text, &pos, " offset-min=");
    _ = appendSigned(&text, &pos, status.offset_minutes);
    _ = append(&text, &pos, " date=");
    _ = appendDec(&text, &pos, status.local_year);
    _ = append(&text, &pos, "-");
    _ = appendDec(&text, &pos, status.local_month);
    _ = append(&text, &pos, "-");
    _ = appendDec(&text, &pos, status.local_day);
    _ = append(&text, &pos, " format=");
    _ = append(&text, &pos, if (status.clock_format == r4os.abi.clock_format_12h) "12h" else "24h");
    addRecordEx(ctx, state, r4os.abi.log_service_source_service, r4os.abi.log_severity_info, r4os.abi.log_record_type_status_snapshot, "TIMESVC", text[0..pos], 0);
}

fn addAudioServiceSnapshot(ctx: *const r4os.r4sys.Context, state: *LogState) void {
    var status = r4os.abi.AudioServiceStatus{};
    if (ctx.audioServiceStatus(&status) != r4os.abi.service_api_result_ok) return;

    var text: [r4os.abi.log_service_text_bytes]u8 = .{0} ** r4os.abi.log_service_text_bytes;
    var pos: usize = 0;
    _ = append(&text, &pos, "audio-service sessions=");
    _ = appendDec(&text, &pos, status.open_sessions);
    _ = append(&text, &pos, "/");
    _ = appendDec(&text, &pos, status.max_sessions);
    _ = append(&text, &pos, " bytes=");
    _ = appendDec(&text, &pos, status.bytes_written);
    _ = append(&text, &pos, " backend=");
    const backend = spanZ(status.backend_name[0..]);
    _ = append(&text, &pos, if (backend.len == 0) "none" else backend);
    const last_error = spanZ(status.last_error[0..]);
    if (last_error.len > 0) {
        _ = append(&text, &pos, " last_error=");
        _ = append(&text, &pos, last_error);
    }
    addRecordEx(ctx, state, r4os.abi.log_service_source_service, r4os.abi.log_severity_info, r4os.abi.log_record_type_status_snapshot, "AUDSVC", text[0..pos], 0);
}

fn refreshConsoleSnapshots(ctx: *const r4os.r4sys.Context, state: *LogState) void {
    const allocator = ctx.allocator();
    var programs: std.ArrayList(r4os.abi.ProgramInstanceInfo) = .empty;
    defer programs.deinit(allocator);

    var attempt: u32 = 0;
    snapshot: while (attempt < inventory_restart_limit) : (attempt += 1) {
        programs.clearRetainingCapacity();
        var cursor: r4os.abi.ProgramInventoryCursor = .{};
        var summary: r4os.abi.ProgramInventorySummary = .{};
        if (!beginProgramInventory(ctx, &cursor, &summary)) return;
        programs.ensureTotalCapacity(allocator, @intCast(summary.program_total)) catch return;
        while (true) {
            var entries: [@as(usize, r4os.abi.program_inventory_page_max)]r4os.abi.ProgramInstanceSnapshot = undefined;
            var page: r4os.abi.ProgramInventoryPageInfo = .{};
            if (!readProgramInventoryPage(ctx, &cursor, entries[0..], &page)) return;
            if (page.status == r4os.abi.program_inventory_status_restart) continue :snapshot;
            if (page.returned > entries.len or page.snapshot_generation != cursor.snapshot_generation) return;
            for (entries[0..@intCast(page.returned)]) |entry| {
                programs.append(allocator, entry.info) catch return;
            }
            if (page.status == r4os.abi.program_inventory_status_complete) break;
            if (page.status != r4os.abi.program_inventory_status_more or page.returned == 0) return;
        }

        // Only emit records after every page came from one stable generation;
        // a restart therefore cannot duplicate records from an abandoned pass.
        for (programs.items) |info| {
            if (info.app_class != @intFromEnum(r4os.abi.ProgramInstanceClass.console)) continue;

            var console = r4os.abi.ConsoleState{};
            if (ctx.consoleState(info.id, &console) != 0) continue;
            addConsoleSnapshot(ctx, state, &info, &console);
        }
        return;
    }
}

fn beginProgramInventory(
    ctx: *const r4os.r4sys.Context,
    cursor: *r4os.abi.ProgramInventoryCursor,
    summary: *r4os.abi.ProgramInventorySummary,
) bool {
    var retry: u32 = 0;
    while (retry <= inventory_would_block_retry_limit) : (retry += 1) {
        cursor.* = .{};
        summary.* = .{};
        const status = ctx.programInventoryBegin(cursor, summary);
        if (status == r4os.abi.program_handle_ok) return true;
        if (status != r4os.abi.program_handle_error_would_block or retry == inventory_would_block_retry_limit)
            return false;
        ctx.sleepTicks(1);
    }
    return false;
}

fn readProgramInventoryPage(
    ctx: *const r4os.r4sys.Context,
    cursor: *r4os.abi.ProgramInventoryCursor,
    entries: []r4os.abi.ProgramInstanceSnapshot,
    page: *r4os.abi.ProgramInventoryPageInfo,
) bool {
    var retry: u32 = 0;
    while (retry <= inventory_would_block_retry_limit) : (retry += 1) {
        const cursor_before = cursor.*;
        page.* = .{};
        const status = ctx.programInventoryPrograms(cursor, entries, page);
        if (status == r4os.abi.program_handle_ok) return true;
        cursor.* = cursor_before;
        page.* = .{};
        if (status != r4os.abi.program_handle_error_would_block or retry == inventory_would_block_retry_limit)
            return false;
        ctx.sleepTicks(1);
    }
    return false;
}

fn addConsoleSnapshot(ctx: *const r4os.r4sys.Context, state: *LogState, info: *const r4os.abi.ProgramInstanceInfo, console: *const r4os.abi.ConsoleState) void {
    var origin: [r4os.abi.log_service_origin_bytes]u8 = .{0} ** r4os.abi.log_service_origin_bytes;
    var origin_pos: usize = 0;
    _ = append(&origin, &origin_pos, "PID ");
    _ = appendDec(&origin, &origin_pos, info.id);

    var text: [r4os.abi.log_service_text_bytes]u8 = .{0} ** r4os.abi.log_service_text_bytes;
    var pos: usize = 0;
    _ = append(&text, &pos, "role=");
    _ = append(&text, &pos, programRoleName(info.role));
    _ = append(&text, &pos, " state=");
    _ = append(&text, &pos, programStateName(info.state));
    _ = append(&text, &pos, " output_len=");
    _ = appendDec(&text, &pos, console.output_len);
    _ = append(&text, &pos, " dropped=");
    _ = appendDec(&text, &pos, console.output_dropped_bytes);
    _ = append(&text, &pos, " lines=");
    _ = appendDec(&text, &pos, console.scrollback_lines);
    _ = append(&text, &pos, " stdout=");
    _ = appendDec(&text, &pos, console.stdout_bytes);
    _ = append(&text, &pos, " stderr=");
    _ = appendDec(&text, &pos, console.stderr_bytes);
    addRecordEx(ctx, state, r4os.abi.log_service_source_console, r4os.abi.log_severity_info, r4os.abi.log_record_type_console_output, spanZ(origin[0..]), text[0..pos], if (console.output_dropped_bytes > 0) r4os.abi.log_service_record_flag_truncated else 0);
}

fn refreshFileSource(ctx: *const r4os.r4sys.Context, state: *LogState) void {
    if (state.file_adapter_checked) return;
    state.file_adapter_checked = true;

    const read = ctx.fileRead(file_log_path, file_log_buffer[0..]);
    if (read <= 0) {
        addRecordEx(ctx, state, r4os.abi.log_service_source_file, r4os.abi.log_severity_info, r4os.abi.log_record_type_status_snapshot, "SYSTEM.LOG", "Fixed file source C:\\R4OS\\LOGS\\SYSTEM.LOG is configured; no file present", 0);
        return;
    }

    const len: usize = @intCast(read);
    var start: usize = 0;
    var i: usize = 0;
    var imported: u32 = 0;
    while (i < len and imported < 16) {
        while (i < len and file_log_buffer[i] != '\r' and file_log_buffer[i] != '\n') : (i += 1) {}
        if (i > start) {
            addRecordEx(ctx, state, r4os.abi.log_service_source_file, r4os.abi.log_severity_info, r4os.abi.log_record_type_file_record, "SYSTEM.LOG", file_log_buffer[start..i], r4os.abi.log_service_record_flag_imported);
            imported += 1;
        }
        while (i < len and (file_log_buffer[i] == '\r' or file_log_buffer[i] == '\n')) : (i += 1) {}
        start = i;
    }
}

fn handleRequest(ctx: *const r4os.r4sys.Context, dev: ?*const r4os.r4dev.Context, handle: u32, state: *LogState) i32 {
    var header: r4os.abi.ServiceMessageHeader = .{};
    const got = ctx.serviceEndpointRecv(handle, &header, service_payload[0..]);
    if (got < 0) return got;
    if (got == 0 and header.magic != r4os.abi.service_api_magic) return 0;

    state.requests +%= 1;
    refreshAdapters(ctx, dev, state);
    const payload_len: usize = @intCast(got);
    return switch (header.op) {
        r4os.abi.log_service_op_status => replyStatus(ctx, handle, header.request_id, state),
        r4os.abi.log_service_op_sources => replySources(ctx, handle, header.request_id, state, service_payload[0..payload_len]),
        r4os.abi.log_service_op_records => replyRecords(ctx, handle, header.request_id, state, service_payload[0..payload_len]),
        r4os.abi.log_service_op_write => handleWrite(ctx, handle, header.request_id, state, service_payload[0..payload_len]),
        r4os.abi.log_service_op_export => replyExport(ctx, handle, header.request_id, state, service_payload[0..payload_len]),
        else => {
            state.bad_ops +%= 1;
            setLastError(state, "bad-op");
            return ctx.serviceEndpointReply(handle, header.request_id, r4os.abi.service_api_result_bad_op, "BADOP");
        },
    };
}

fn replyStatus(ctx: *const r4os.r4sys.Context, handle: u32, request_id: u32, state: *const LogState) i32 {
    const status = makeStatus(state);
    const bytes: [*]const u8 = @ptrCast(&status);
    return ctx.serviceEndpointReply(handle, request_id, r4os.abi.service_api_result_ok, bytes[0..@sizeOf(r4os.abi.LogServiceStatus)]);
}

fn replySources(ctx: *const r4os.r4sys.Context, handle: u32, request_id: u32, state: *const LogState, payload: []const u8) i32 {
    var query = r4os.abi.LogServiceSourceQuery{};
    if (payload.len != 0 and !parseSourceQuery(payload, &query)) {
        return ctx.serviceEndpointReply(handle, request_id, r4os.abi.service_api_result_invalid, "");
    }

    var page = r4os.abi.LogServiceSourcePage{
        .total_sources = @intCast(r4os.abi.log_service_source_count),
        .start_index = query.start_index,
        .revision = state.revision,
    };

    const source_count_u32: u32 = @intCast(r4os.abi.log_service_source_count);
    const max_sources: u16 = @intCast(@min(@min(query.max_sources, @as(u32, @intCast(r4os.abi.log_service_sources_per_page))), source_count_u32));
    var logical = query.start_index;
    while (page.count < max_sources and logical < source_count_u32) : (logical += 1) {
        const source_id: u32 = logical + 1;
        page.sources[@intCast(page.count)] = makeSourceInfo(state, source_id);
        page.count += 1;
    }
    page.next_index = logical;
    if (logical < source_count_u32) page.flags |= r4os.abi.log_service_page_flag_more;

    const bytes: [*]const u8 = @ptrCast(&page);
    return ctx.serviceEndpointReply(handle, request_id, r4os.abi.service_api_result_ok, bytes[0..@sizeOf(r4os.abi.LogServiceSourcePage)]);
}

fn replyRecords(ctx: *const r4os.r4sys.Context, handle: u32, request_id: u32, state: *const LogState, payload: []const u8) i32 {
    var query = r4os.abi.LogServiceRecordQuery{};
    if (!parseRecordQuery(payload, &query)) {
        return ctx.serviceEndpointReply(handle, request_id, r4os.abi.service_api_result_invalid, "");
    }
    if (!validSourceFilter(query.source_id)) {
        return ctx.serviceEndpointReply(handle, request_id, r4os.abi.service_api_result_invalid, "");
    }

    var page = makeRecordPage(state, &query);
    const bytes: [*]const u8 = @ptrCast(&page);
    return ctx.serviceEndpointReply(handle, request_id, r4os.abi.service_api_result_ok, bytes[0..@sizeOf(r4os.abi.LogServiceRecordPage)]);
}

fn handleWrite(ctx: *const r4os.r4sys.Context, handle: u32, request_id: u32, state: *LogState, payload: []const u8) i32 {
    var request = r4os.abi.LogServiceWriteRequest{};
    if (!parseWriteRequest(payload, &request) or !validSeverity(request.severity)) {
        return ctx.serviceEndpointReply(handle, request_id, r4os.abi.service_api_result_invalid, "");
    }

    const origin = boundedSpan(request.origin[0..], request.origin_len);
    const text = boundedSpan(request.text[0..], request.text_len);
    addRecordEx(ctx, state, request.source_id, request.severity, request.record_type, if (origin.len == 0) "APP" else origin, text, request.flags);
    state.writes +%= 1;
    setLastError(state, "ready");
    return replyStatus(ctx, handle, request_id, state);
}

fn replyExport(ctx: *const r4os.r4sys.Context, handle: u32, request_id: u32, state: *LogState, payload: []const u8) i32 {
    var query = r4os.abi.LogServiceRecordQuery{};
    if (!parseRecordQuery(payload, &query)) {
        return ctx.serviceEndpointReply(handle, request_id, r4os.abi.service_api_result_invalid, "");
    }
    if (!validSourceFilter(query.source_id)) {
        return ctx.serviceEndpointReply(handle, request_id, r4os.abi.service_api_result_invalid, "");
    }

    var page = makeExportPage(state, &query);
    state.exports +%= 1;
    const bytes: [*]const u8 = @ptrCast(&page);
    return ctx.serviceEndpointReply(handle, request_id, r4os.abi.service_api_result_ok, bytes[0..@sizeOf(r4os.abi.LogServiceExportPage)]);
}

fn addRecordEx(ctx: *const r4os.r4sys.Context, state: *LogState, source_id_raw: u32, severity_raw: u8, record_type_raw: u8, origin: []const u8, text: []const u8, flags: u32) void {
    const source_id = normalizeSource(source_id_raw);
    const severity = normalizeSeverity(severity_raw);
    const record_type = normalizeRecordType(record_type_raw);

    if (state.count == r4os.abi.log_service_max_records) {
        const old = &state.records[state.write_index];
        if (sourceIndex(old.source_id)) |idx| state.source_dropped[idx] +%= 1;
        state.dropped_records +%= 1;
    } else {
        state.count += 1;
    }

    var record = &state.records[state.write_index];
    record.* = .{
        .severity = severity,
        .source_kind = @intCast(source_id),
        .record_type = record_type,
        .source_id = source_id,
        .flags = flags,
        .sequence = state.next_sequence,
        .ticks = ctx.ticks(),
    };
    record.origin_len = @intCast(copyBounded(record.origin[0..], origin));
    record.text_len = copyBounded(record.text[0..], text);
    if (text.len > @as(usize, record.text_len)) record.flags |= r4os.abi.log_service_record_flag_truncated;

    if (sourceIndex(source_id)) |idx| {
        state.source_total[idx] +%= 1;
        state.source_last_sequence[idx] = record.sequence;
    }
    switch (source_id) {
        r4os.abi.log_service_source_application => state.app_records +%= 1,
        r4os.abi.log_service_source_service => state.service_records +%= 1,
        r4os.abi.log_service_source_console => state.console_records +%= 1,
        r4os.abi.log_service_source_diagnostic => state.diagnostic_records +%= 1,
        r4os.abi.log_service_source_file => state.file_records +%= 1,
        else => {},
    }

    state.next_sequence +%= 1;
    state.revision +%= 1;
    if (state.revision == 0) state.revision = 1;
    state.write_index = (state.write_index + 1) % r4os.abi.log_service_max_records;
}

fn makeStatus(state: *const LogState) r4os.abi.LogServiceStatus {
    var out = r4os.abi.LogServiceStatus{
        .flags = if (state.bootlog_loaded) r4os.abi.log_service_status_flag_bootlog_loaded else 0,
        .revision = state.revision,
        .source_count = @intCast(r4os.abi.log_service_source_count),
        .record_count = @intCast(state.count),
        .record_capacity = @intCast(r4os.abi.log_service_max_records),
        .bootlog_bytes = state.bootlog_bytes,
        .bootlog_records = state.bootlog_records,
        .app_records = state.app_records,
        .bad_ops = state.bad_ops,
        .total_records = state.next_sequence - 1,
        .dropped_records = state.dropped_records,
        .requests = state.requests,
        .writes = state.writes,
        .exports = state.exports,
    };
    copyFixedZ(out.last_error[0..], spanZ(state.last_error[0..]));
    return out;
}

fn makeSourceInfo(state: *const LogState, source_id: u32) r4os.abi.LogServiceSourceInfo {
    var out = r4os.abi.LogServiceSourceInfo{
        .id = source_id,
        .kind = @intCast(source_id),
        .stored_records = storedRecordsForSource(state, source_id),
    };
    if (sourceIndex(source_id)) |idx| {
        out.total_records = state.source_total[idx];
        out.dropped_records = state.source_dropped[idx];
        out.last_sequence = state.source_last_sequence[idx];
    }
    switch (source_id) {
        r4os.abi.log_service_source_bootlog => {
            copyFixedZ(out.name[0..], "Bootlog");
            copyFixedZ(out.description[0..], "Imported boot ringbuffer records");
        },
        r4os.abi.log_service_source_driver => {
            copyFixedZ(out.name[0..], "Driver");
            copyFixedZ(out.description[0..], "R4D log events imported from bootlog");
        },
        r4os.abi.log_service_source_protocol => {
            copyFixedZ(out.name[0..], "Protocol");
            copyFixedZ(out.description[0..], "R4P log events imported from bootlog");
        },
        r4os.abi.log_service_source_application => {
            copyFixedZ(out.name[0..], "Application");
            copyFixedZ(out.description[0..], "Application records sent through LOGSVC");
        },
        r4os.abi.log_service_source_service => {
            copyFixedZ(out.name[0..], "Service");
            copyFixedZ(out.description[0..], "Service registry and service endpoint snapshots");
        },
        r4os.abi.log_service_source_console => {
            copyFixedZ(out.name[0..], "Console");
            copyFixedZ(out.description[0..], "Console instance scrollback and state snapshots");
        },
        r4os.abi.log_service_source_diagnostic => {
            copyFixedZ(out.name[0..], "Diagnostic");
            copyFixedZ(out.description[0..], "Explicit diagnostic snapshot records");
        },
        r4os.abi.log_service_source_file => {
            copyFixedZ(out.name[0..], "File");
            copyFixedZ(out.description[0..], "Fixed log file source under C:\\R4OS\\LOGS");
        },
        else => {},
    }
    return out;
}

fn makeRecordPage(state: *const LogState, query: *const r4os.abi.LogServiceRecordQuery) r4os.abi.LogServiceRecordPage {
    var page = r4os.abi.LogServiceRecordPage{
        .start_index = query.start_index,
        .revision = state.revision,
    };
    const max_records: u16 = @intCast(@min(query.max_records, @as(u32, @intCast(r4os.abi.log_service_records_per_page))));
    const search = spanZ(query.search[0..]);
    var match_index: u32 = 0;
    var logical: usize = 0;
    while (logical < state.count) : (logical += 1) {
        const record = recordAt(state, logical);
        if (!recordMatches(record, query, search)) continue;
        if (match_index >= query.start_index and page.count < max_records) {
            page.records[@intCast(page.count)] = record.*;
            page.count += 1;
        }
        match_index += 1;
    }
    page.total_matches = match_index;
    page.next_index = query.start_index + @as(u32, page.count);
    if (page.next_index < page.total_matches) page.flags |= r4os.abi.log_service_page_flag_more;
    return page;
}

fn makeExportPage(state: *const LogState, query: *const r4os.abi.LogServiceRecordQuery) r4os.abi.LogServiceExportPage {
    var page = r4os.abi.LogServiceExportPage{
        .revision = state.revision,
        .start_index = query.start_index,
    };
    const search = spanZ(query.search[0..]);
    var match_index: u32 = 0;
    var logical: usize = 0;
    var pos: usize = 0;
    while (logical < state.count) : (logical += 1) {
        const record = recordAt(state, logical);
        if (!recordMatches(record, query, search)) continue;
        if (match_index >= query.start_index) {
            if (!appendRecordLine(page.text[0..], &pos, record)) {
                page.flags |= r4os.abi.log_service_page_flag_more;
                break;
            }
        }
        match_index += 1;
    }
    page.total_matches = countMatches(state, query, search);
    page.next_index = query.start_index + countExportedLines(page.text[0..pos]);
    if (page.next_index < page.total_matches) page.flags |= r4os.abi.log_service_page_flag_more;
    page.bytes = @intCast(pos);
    return page;
}

fn recordAt(state: *const LogState, logical_index: usize) *const r4os.abi.LogServiceRecord {
    const oldest = if (state.count == r4os.abi.log_service_max_records) state.write_index else 0;
    return &state.records[(oldest + logical_index) % r4os.abi.log_service_max_records];
}

fn recordMatches(record: *const r4os.abi.LogServiceRecord, query: *const r4os.abi.LogServiceRecordQuery, search: []const u8) bool {
    if (query.source_id != r4os.abi.log_service_source_any and record.source_id != query.source_id) return false;
    if (record.severity < query.severity_min) return false;
    if (search.len == 0) return true;
    return containsIgnoreCase(record.text[0..@as(usize, record.text_len)], search) or containsIgnoreCase(record.origin[0..@as(usize, record.origin_len)], search);
}

fn countMatches(state: *const LogState, query: *const r4os.abi.LogServiceRecordQuery, search: []const u8) u32 {
    var count: u32 = 0;
    var i: usize = 0;
    while (i < state.count) : (i += 1) {
        if (recordMatches(recordAt(state, i), query, search)) count += 1;
    }
    return count;
}

fn storedRecordsForSource(state: *const LogState, source_id: u32) u32 {
    var count: u32 = 0;
    var i: usize = 0;
    while (i < state.count) : (i += 1) {
        if (recordAt(state, i).source_id == source_id) count += 1;
    }
    return count;
}

fn appendRecordLine(out: []u8, pos: *usize, record: *const r4os.abi.LogServiceRecord) bool {
    const before = pos.*;
    if (!appendDec(out, pos, record.sequence)) return restore(out, pos, before);
    if (!append(out, pos, " ")) return restore(out, pos, before);
    if (!append(out, pos, severityName(record.severity))) return restore(out, pos, before);
    if (!append(out, pos, " ")) return restore(out, pos, before);
    if (!append(out, pos, recordTypeName(record.record_type))) return restore(out, pos, before);
    if (!append(out, pos, " ")) return restore(out, pos, before);
    if (!append(out, pos, record.origin[0..@as(usize, record.origin_len)])) return restore(out, pos, before);
    if (!append(out, pos, " ")) return restore(out, pos, before);
    if (!append(out, pos, record.text[0..@as(usize, record.text_len)])) return restore(out, pos, before);
    if (!append(out, pos, "\r\n")) return restore(out, pos, before);
    return true;
}

fn restore(out: []u8, pos: *usize, before: usize) bool {
    if (before < out.len) @memset(out[before..pos.*], 0);
    pos.* = before;
    return false;
}

fn countExportedLines(text: []const u8) u32 {
    var count: u32 = 0;
    var i: usize = 0;
    while (i < text.len) : (i += 1) {
        if (text[i] == '\n') count += 1;
    }
    return count;
}

fn parseSourceQuery(payload: []const u8, out: *r4os.abi.LogServiceSourceQuery) bool {
    if (payload.len < @sizeOf(r4os.abi.LogServiceSourceQuery)) return false;
    const bytes: [*]u8 = @ptrCast(out);
    @memcpy(bytes[0..@sizeOf(r4os.abi.LogServiceSourceQuery)], payload[0..@sizeOf(r4os.abi.LogServiceSourceQuery)]);
    return out.magic == r4os.abi.log_service_query_magic and out.version == r4os.abi.log_service_version;
}

fn parseRecordQuery(payload: []const u8, out: *r4os.abi.LogServiceRecordQuery) bool {
    if (payload.len < @sizeOf(r4os.abi.LogServiceRecordQuery)) return false;
    const bytes: [*]u8 = @ptrCast(out);
    @memcpy(bytes[0..@sizeOf(r4os.abi.LogServiceRecordQuery)], payload[0..@sizeOf(r4os.abi.LogServiceRecordQuery)]);
    return out.magic == r4os.abi.log_service_query_magic and out.version == r4os.abi.log_service_version and validSeverity(out.severity_min);
}

fn parseWriteRequest(payload: []const u8, out: *r4os.abi.LogServiceWriteRequest) bool {
    if (payload.len < @sizeOf(r4os.abi.LogServiceWriteRequest)) return false;
    const bytes: [*]u8 = @ptrCast(out);
    @memcpy(bytes[0..@sizeOf(r4os.abi.LogServiceWriteRequest)], payload[0..@sizeOf(r4os.abi.LogServiceWriteRequest)]);
    return out.magic == r4os.abi.log_service_write_magic and out.version == r4os.abi.log_service_version and validSourceFilter(out.source_id) and validRecordType(out.record_type);
}

fn validSourceFilter(source_id: u32) bool {
    return source_id == r4os.abi.log_service_source_any or sourceIndex(source_id) != null;
}

fn sourceIndex(source_id: u32) ?usize {
    if (source_id >= 1 and source_id <= @as(u32, @intCast(r4os.abi.log_service_source_count))) return @intCast(source_id);
    return null;
}

fn normalizeSource(source_id: u32) u32 {
    return if (sourceIndex(source_id) != null) source_id else r4os.abi.log_service_source_application;
}

fn validSeverity(severity: u8) bool {
    return severity <= r4os.abi.log_severity_error;
}

fn normalizeSeverity(severity: u8) u8 {
    return if (validSeverity(severity)) severity else r4os.abi.log_severity_info;
}

fn validRecordType(record_type: u8) bool {
    return record_type <= r4os.abi.log_record_type_file_record;
}

fn normalizeRecordType(record_type: u8) u8 {
    return if (validRecordType(record_type)) record_type else r4os.abi.log_record_type_event;
}

fn parseSeverity(value: []const u8) u8 {
    if (equalsIgnoreCase(value, "Debug")) return r4os.abi.log_severity_debug;
    if (equalsIgnoreCase(value, "Warn")) return r4os.abi.log_severity_warn;
    if (equalsIgnoreCase(value, "Error")) return r4os.abi.log_severity_error;
    return r4os.abi.log_severity_info;
}

fn severityName(severity: u8) []const u8 {
    return switch (severity) {
        r4os.abi.log_severity_debug => "Debug",
        r4os.abi.log_severity_warn => "Warn",
        r4os.abi.log_severity_error => "Error",
        else => "Info",
    };
}

fn recordTypeName(record_type: u8) []const u8 {
    return switch (record_type) {
        r4os.abi.log_record_type_status_snapshot => "StatusSnapshot",
        r4os.abi.log_record_type_console_output => "ConsoleOutput",
        r4os.abi.log_record_type_diagnostic_snapshot => "DiagnosticSnapshot",
        r4os.abi.log_record_type_file_record => "FileRecord",
        else => "Event",
    };
}

fn severityForService(state: u32) u8 {
    return switch (state) {
        r4os.abi.service_state_failed => r4os.abi.log_severity_error,
        r4os.abi.service_state_disabled => r4os.abi.log_severity_warn,
        else => r4os.abi.log_severity_info,
    };
}

fn serviceStateName(raw: u32) []const u8 {
    return switch (raw) {
        r4os.abi.service_state_stopped => "stopped",
        r4os.abi.service_state_starting => "starting",
        r4os.abi.service_state_running => "running",
        r4os.abi.service_state_stopping => "stopping",
        r4os.abi.service_state_failed => "failed",
        r4os.abi.service_state_disabled => "disabled",
        else => "empty",
    };
}

fn serviceStartName(raw: u32) []const u8 {
    return switch (raw) {
        r4os.abi.service_start_auto => "auto",
        r4os.abi.service_start_disabled => "disabled",
        else => "manual",
    };
}

fn programRoleName(raw: u8) []const u8 {
    return switch (raw) {
        @intFromEnum(r4os.abi.ProgramInstanceRole.foreground) => "foreground",
        @intFromEnum(r4os.abi.ProgramInstanceRole.shell) => "shell",
        @intFromEnum(r4os.abi.ProgramInstanceRole.background) => "background",
        else => "unknown",
    };
}

fn programStateName(raw: u8) []const u8 {
    return switch (raw) {
        @intFromEnum(r4os.abi.ProgramInstanceState.running) => "running",
        @intFromEnum(r4os.abi.ProgramInstanceState.close_requested) => "close-requested",
        @intFromEnum(r4os.abi.ProgramInstanceState.done) => "done",
        else => "unknown",
    };
}

fn valueAfter(text: []const u8, key: []const u8) ?[]const u8 {
    const start = afterPattern(text, key) orelse return null;
    var end: usize = 0;
    while (end < start.len and start[end] != ' ' and start[end] != '\t') : (end += 1) {}
    return start[0..end];
}

fn afterPattern(text: []const u8, pattern: []const u8) ?[]const u8 {
    if (pattern.len == 0 or pattern.len > text.len) return null;
    var i: usize = 0;
    while (i + pattern.len <= text.len) : (i += 1) {
        var j: usize = 0;
        while (j < pattern.len and text[i + j] == pattern[j]) : (j += 1) {}
        if (j == pattern.len) return text[i + pattern.len ..];
    }
    return null;
}

fn boundedSpan(bytes: []const u8, declared_len: u16) []const u8 {
    var count: usize = @min(bytes.len, @as(usize, declared_len));
    var i: usize = 0;
    while (i < count) : (i += 1) {
        if (bytes[i] == 0) {
            count = i;
            break;
        }
    }
    return bytes[0..count];
}

fn spanZ(bytes: []const u8) []const u8 {
    var len: usize = 0;
    while (len < bytes.len and bytes[len] != 0) : (len += 1) {}
    return bytes[0..len];
}

fn copyBounded(out: []u8, value: []const u8) u16 {
    @memset(out, 0);
    if (out.len == 0) return 0;
    const count = @min(value.len, out.len - 1);
    if (count > 0) @memcpy(out[0..count], value[0..count]);
    return @intCast(count);
}

fn copyFixedZ(out: []u8, value: []const u8) void {
    _ = copyBounded(out, value);
}

fn setLastError(state: *LogState, value: []const u8) void {
    copyFixedZ(state.last_error[0..], value);
}

fn append(out: []u8, pos: *usize, value: []const u8) bool {
    if (pos.* + value.len > out.len) return false;
    if (value.len > 0) @memcpy(out[pos.* .. pos.* + value.len], value);
    pos.* += value.len;
    return true;
}

fn appendDec(out: []u8, pos: *usize, value: u64) bool {
    var buf: [20]u8 = .{0} ** 20;
    var n = value;
    var len: usize = 0;
    if (n == 0) {
        buf[buf.len - 1] = '0';
        len = 1;
    } else {
        while (n != 0 and len < buf.len) : (len += 1) {
            buf[buf.len - 1 - len] = @intCast('0' + (n % 10));
            n /= 10;
        }
    }
    return append(out, pos, buf[buf.len - len ..]);
}

fn appendSigned(out: []u8, pos: *usize, value: i32) bool {
    if (value < 0) {
        if (!append(out, pos, "-")) return false;
        const magnitude: u64 = @intCast(-(value + 1));
        return appendDec(out, pos, magnitude + 1);
    }
    return appendDec(out, pos, @intCast(value));
}

fn containsIgnoreCase(haystack: []const u8, needle: []const u8) bool {
    if (needle.len == 0) return true;
    if (needle.len > haystack.len) return false;
    var i: usize = 0;
    while (i + needle.len <= haystack.len) : (i += 1) {
        var j: usize = 0;
        while (j < needle.len and upper(haystack[i + j]) == upper(needle[j])) : (j += 1) {}
        if (j == needle.len) return true;
    }
    return false;
}

fn startsWith(text: []const u8, prefix: []const u8) bool {
    if (prefix.len > text.len) return false;
    return equals(text[0..prefix.len], prefix);
}

fn equals(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var i: usize = 0;
    while (i < a.len) : (i += 1) {
        if (a[i] != b[i]) return false;
    }
    return true;
}

fn equalsIgnoreCase(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var i: usize = 0;
    while (i < a.len) : (i += 1) {
        if (upper(a[i]) != upper(b[i])) return false;
    }
    return true;
}

fn upper(ch: u8) u8 {
    if (ch >= 'a' and ch <= 'z') return ch - ('a' - 'A');
    return ch;
}

fn hasArg(args: [*:0]const u8, wanted: []const u8) bool {
    var offset: usize = 0;
    while (offset < 256 and args[offset] != 0) {
        while (offset < 256 and (args[offset] == ' ' or args[offset] == '\t')) : (offset += 1) {}
        const start = offset;
        while (offset < 256 and args[offset] != 0 and args[offset] != ' ' and args[offset] != '\t') : (offset += 1) {}
        if (equalsIgnoreCase(args[start..offset], wanted)) return true;
    }
    return false;
}

fn waitOpen(ctx: *const r4os.r4sys.Context, out_handle: *u32, max_ticks: u32) bool {
    var tick: u32 = 0;
    while (tick < max_ticks) : (tick += 1) {
        var info: r4os.abi.ServiceInfo = .{};
        const rc = ctx.serviceOpen(service_name, &info);
        if (rc == r4os.abi.service_api_result_ok and info.handle != 0) {
            out_handle.* = info.handle;
            return true;
        }
        ctx.sleepTicks(1);
    }
    return false;
}

fn ensureRunning(ctx: *const r4os.r4sys.Context) bool {
    var info: r4os.abi.ServiceInfo = .{};
    const status = ctx.serviceStatus(service_name, &info);
    if (status != r4os.abi.service_api_result_ok) return false;
    if (info.state == r4os.abi.service_state_running) return true;
    const start = ctx.serviceStart(service_name, &info);
    return start == r4os.abi.service_api_result_ok or start == r4os.abi.service_api_result_running;
}

fn runPing(ctx: *const r4os.r4sys.Context) i32 {
    ctx.println("LOGSVC ping");
    if (!ensureRunning(ctx)) return fail(ctx, "start");
    var status = r4os.abi.LogServiceStatus{};
    if (ctx.logServiceStatus(&status) != r4os.abi.service_api_result_ok) return fail(ctx, "status");
    ctx.println("LOGSVC ping: OK");
    return 0;
}

fn runSelfTest(ctx: *const r4os.r4sys.Context) i32 {
    ctx.println("LOGSVC selftest");
    if (!ctx.hasFn("service_call")) return fail(ctx, "service-api");
    if (!ensureRunning(ctx)) return fail(ctx, "start");

    var handle: u32 = 0;
    if (!waitOpen(ctx, &handle, 160)) return fail(ctx, "open");
    _ = ctx.serviceClose(handle);

    var status = r4os.abi.LogServiceStatus{};
    if (ctx.logServiceStatus(&status) != r4os.abi.service_api_result_ok) return fail(ctx, "status");
    if (status.record_capacity != @as(u32, @intCast(r4os.abi.log_service_max_records)) or status.source_count != @as(u32, @intCast(r4os.abi.log_service_source_count))) return fail(ctx, "status-shape");

    if (ctx.logServiceWrite(r4os.abi.log_severity_info, "LOGSVC", "selftest application record") != r4os.abi.service_api_result_ok) return fail(ctx, "write");
    var query = r4os.abi.LogServiceRecordQuery{
        .source_id = r4os.abi.log_service_source_application,
        .severity_min = r4os.abi.log_severity_info,
    };
    copyFixedZ(query.search[0..], "selftest application record");
    var records = r4os.abi.LogServiceRecordPage{};
    if (ctx.logServiceRecords(&query, &records) != r4os.abi.service_api_result_ok or records.count == 0) return fail(ctx, "records");

    ctx.println("LOGSVC selftest: OK");
    return 0;
}

fn fail(ctx: *const r4os.r4sys.Context, label: []const u8) i32 {
    ctx.write("LOGSVC selftest FAILED: ");
    ctx.println(label);
    return 1;
}
