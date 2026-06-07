# Genesys 2 Board Source Archive

Local archive of external Digilent Genesys 2 board resources used for pin,
constraint, and board bring-up checks.

## Files

| Path | Purpose | Source |
| --- | --- | --- |
| `constraints/Genesys-2-Master.xdc` | Digilent master XDC pin constraints for Genesys 2. | https://github.com/Digilent/digilent-xdc/blob/master/Genesys-2-Master.xdc |
| `constraints/digilent-xdc-License.txt` | License for the Digilent XDC repository. | https://github.com/Digilent/digilent-xdc |
| `vivado-board-files/H/part0_pins.xml` | Vivado board part pin dataset for `digilentinc.com:genesys2:part0:1.1`. | https://github.com/Digilent/vivado-boards/tree/master/new/board_files/genesys2/H |
| `vivado-board-files/H/board.xml` | Vivado board part metadata and interfaces. | https://github.com/Digilent/vivado-boards/tree/master/new/board_files/genesys2/H |
| `vivado-board-files/H/preset.xml` | Vivado board part IP presets. | https://github.com/Digilent/vivado-boards/tree/master/new/board_files/genesys2/H |
| `vivado-board-files/H/mig.prj` | Digilent MIG configuration for the on-board DDR3 interface. | https://github.com/Digilent/vivado-boards/tree/master/new/board_files/genesys2/H |
| `digilent-docs/genesys2_rm.pdf` | Genesys 2 FPGA Board Reference Manual. | https://digilent.com/reference/_media/reference/programmable-logic/genesys-2/genesys2_rm.pdf |
| `digilent-docs/genesys-2_sch.pdf` | Genesys 2 board schematic. | https://digilent.com/reference/_media/reference/programmable-logic/genesys-2/genesys-2_sch.pdf |

The active repository build still follows `fpga/genesys2/README.md`: CVA6's
`rtl/cva6/corev_apu/fpga/constraints/genesys-2.xdc` remains the canonical
active constraints file until a reproducible board gate needs a local overlay.

## SHA-256

```text
2F704AD912640BCBC2E6B900518452E3153D89BF91CEF55D075153107E6C72CE  constraints/Genesys-2-Master.xdc
FBDFAE05E542EA6AD7E11E3818076B46D2B6BD81DAC49C59BC9AC78025BA5339  constraints/digilent-xdc-License.txt
7D07EDF583AC5E22327FDF4919806D80F19D9C3CB9262CF10FDABC4ACE53EFA1  digilent-docs/genesys2_rm.pdf
73A6B396DDCF037A112C2F917D3C9044D246C706E5B8A15431D941CCC5F99C43  digilent-docs/genesys-2_sch.pdf
CD49F6ECCC932DBF7CCBDBB3327A1FBDC352D62C463A730B78B2F17CE7923F3D  vivado-board-files/H/board.xml
3EBD0A6D04613E2BA1F7FDA692479D1212CA97F30714D48F30AE41D6507685EF  vivado-board-files/H/mig.prj
8405B6845E706A191A14AB3B27F99BD14DFE5A3D99F9C3001B0C7B79666550A0  vivado-board-files/H/part0_pins.xml
1B94DCD5A582A0FEC6E875FFF792731627EE35B00152328EFB4FE34D0908B9D3  vivado-board-files/H/preset.xml
```
