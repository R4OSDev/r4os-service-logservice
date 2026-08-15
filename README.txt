LOGSVC.R4X
==========

LOGSVC.R4X ist der Log-Aggregationsservice.

Projektstruktur seit 0.51.19:
- `build.zig` baut den Service als eigenes SDK-Projekt.
- `build.zig.zon` bindet `r4os_sdk` als Paket.
- `module.R4MF` beschreibt Artefakt, Zielpfad, Imports, Startdaten und Contract.

Build:

    cd Code\System\Services\LogService
    ..\..\..\DevTools\Zig\zig.exe build

Ergebnis:

    Code\System\Services\LogService\zig-out\LOGSVC.R4X

Contract:
- R4XStart-Entry: `logsvc_main`
- App-Klasse: `service`
- R4L-Imports: `R4SYS`
- Service-Name: `LOGSVC`
- Standardargumente: `/RUN`
- Zielpfad im Image: `C:\R4OS\SERVICES\LOGSVC.R4X`

Runtime-Bootlog seit 0.59.3:
- LOGSVC importiert nicht nur den Startbestand, sondern folgt im laufenden
  Dienst dem absoluten `BootLogInfo.total_written`-Cursor.
- Ueberholte Leser werden auf den aeltesten erhaltenen Ringinhalt geklemmt;
  bereits importierte Bytes werden nicht dupliziert. Ein zwischen Info und
  Read verschobenes Ringfenster wird per zweitem Info-Snapshot erkannt und
  verworfen. Der Cursor rueckt nur bis zum letzten vollstaendigen Zeilenende
  vor, damit eine noch laufende Kernel-Ausgabe beim Folgeabruf komplett bleibt.
  Ist ihr Anfang durch einen Overrun bereits verloren, wird das Fragment ohne
  erneuten Vollring-Scan bis zum naechsten Zeilenende verworfen.
- `[USBHIDPOLL]` und `[USBHIDWRAP]` erscheinen als Diagnosequelle fuer
  LOGCENTER. Zeilen oberhalb einer Recordgroesse werden verlustfrei geteilt.
- Normale Runtime-Kernelmeldungen bleiben damit nach dem Desktopstart in
  COM1/Bootlog/LOGSVC, ohne den sichtbaren Framebuffer zu ueberschreiben.

Gezielter Vertrag:

    Tests\Gate\Run-DesktopKernelLogRoutingContract0593.ps1
