# Genesys 2 OLED Phase Smoke Test

This standalone design drives the onboard Genesys 2 OLED without touching the
CVA6 top level. It verifies the OLED pinout, power sequencing, SPI path, and a
phase-status text layout that can later be wired into the CVA6 bring-up flow.

The display is a 128x32 monochrome SSD1306 panel. It shows four 8-pixel text
rows:

```text
RVMT OLED STATUS
P<n> <phase name>
AUTO CYCLE P0-P7    or    MANUAL SW2:0 SELECT
GENESYS2 128X32
```

Switches:

- `SW3 = 0`: automatically cycles through phases P0-P7.
- `SW3 = 1`: manual mode; `SW2:SW0` selects the displayed phase.

Build:

```powershell
D:/Application/vivado/2025.2/Vivado/bin/vivado.bat -mode batch -source fpga/genesys2/oled_phase_test/build_oled_phase_test.tcl
```

Program:

```powershell
D:/Application/vivado/2025.2/Vivado/bin/vivado.bat -mode batch -source fpga/genesys2/oled_phase_test/program_oled_phase_test.tcl
```

The generated bitstream is written to
`build/vivado/genesys2-oled-phase-test/genesys2_oled_phase_test.bit`.
