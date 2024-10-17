# OpenDBG
Insyde's OpenDBG UEFI debug target, compatible with GDB

#	Driver list:
1.	GdbStub/GdbStubPei : GDB stub PEI driver, created by Insyde
2.	GdbStub/GdbStubDxe : GDB stub DXE driver, copied from EDK2/EmbeddedPkg, we added features(below) on in
3.	Universal/DebugSupportPei : Debug support PPI which consumed by GdbStubPei for the registration of CPU exception and periodic timer handler, created by Insyde
4.	Universal/DebugSupportDxe : Debug support protocol which consumed by GdbStubDxe for the registration of CPU exception and periodic timer handler, copied from EDK2/MdeModulePkg, we changed the definition of SYSTEM_TIMER_VECTOR to PcdSystemTimerVector for easy customization
5.	Library/GdbSerialLib : GDB serial port library for transport layer, copied from EDK2/EmbeddedPkg, we changed it to base library for used by both of PEI and DXE GdbStub driver
#	New features:
1.	Added the loading flow of symbolic information for source level debugging
2.	Added PcdGdbDebugConfigFlags for the control of (1) Break on GdbStub driver initialization (2) Show Information of loaded module (3) Show debug log
3.	Added the display of PCI device and registers by GDB “monitor p” command
#	Unfinished features:
1.	DXE phase debug log
2.	Display of MTRR/MSR registers
3.	Display of I/O registers
4.	Support of SMM/MM
5.	Support of ARM/AARCH64
