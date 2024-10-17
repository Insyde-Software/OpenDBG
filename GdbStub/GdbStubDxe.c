/** @file
  UEFI driver that implements a GDB stub

  This is a GDB stub driver that which communicates with the debugger over
  a physical transport

  Copyright (c) 2008 - 2009, Apple Inc. All rights reserved.<BR>
  Copyright (c) 2024, Insyde Software Corp. All rights reserved.<BR>

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <GdbStubInternal.h>

VOID       *gGdbSymbolEventHandlerRegistration = NULL;

VOID
EFIAPI
GdbSymbolEventHandler (
  IN  EFI_EVENT  Event,
  IN  VOID       *Context
  )
{
  EFI_STATUS                    Status;
  UINTN                         HandleSize;
  EFI_HANDLE                    Handle;
  EFI_LOADED_IMAGE_PROTOCOL     *LoadedImage;
  UINTN                         Index;
  UINTN                         End;
  CHAR8                         StringBuffer[0x100];

  while (TRUE) {
    HandleSize = sizeof(EFI_HANDLE);
    Status = gBS->LocateHandle (
                    ByRegisterNotify,
                    &gEfiLoadedImageProtocolGuid,
                    gGdbSymbolEventHandlerRegistration,
                    &HandleSize,
                    &Handle
                    );
    if (Status != EFI_SUCCESS) break;
    Status = gBS->HandleProtocol (
                    Handle,
                    &gEfiLoadedImageProtocolGuid,
                    (VOID**)&LoadedImage
                    );
    if (Status != EFI_SUCCESS) break;
    gLoadedImageDebugPath = PeCoffLoaderGetDebuggerInfo (
                              LoadedImage->ImageBase,
                              &gLoadedImageBase,
                              &gLoadedImageCodeBase
                              );
    if (PcdGet32 (PcdGdbDebugConfigFlags) & GDB_LOADED_MODULE_INFO_ENABLED) {
      if (gLoadedImageDebugPath != NULL) {
        for (Index = End = AsciiStrLen (gLoadedImageDebugPath) - 1; Index >= 0; Index --) {
          if (gLoadedImageDebugPath[Index] == '.') End = Index;
          else if (gLoadedImageDebugPath[Index] == '/' || gLoadedImageDebugPath[Index] == '\\') {
            Index ++;
            break;
          }
        }
        AsciiSPrint (StringBuffer, 0x100, "[DXE] %a", &gLoadedImageDebugPath[Index]);
        AsciiSPrint (&StringBuffer[6 + (End - Index)], 0x100, ".efi at 0x%012X\n\r", gLoadedImageBase);
        OutputDebugString (StringBuffer);
      }
    }
  }
}

/**
  The user Entry Point for Application. The user code starts with this function
  as the real entry point for the image goes into a library that calls this
  function.

  @param[in] ImageHandle    The firmware allocated handle for the EFI image.
  @param[in] SystemTable    A pointer to the EFI System Table.

  @retval EFI_SUCCESS       The entry point is executed successfully.
  @retval other             Some error occurs when executing this entry point.

**/
EFI_STATUS
EFIAPI
GdbStubDxeEntry (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS                  Status;
  EFI_DEBUG_SUPPORT_PROTOCOL  *DebugSupport;
  UINTN                       MaxProcessorIndex;
  UINTN                       HandleCount;
  EFI_HANDLE                  *Handles;
  UINTN                       Index;
  UINTN                       Processor;
  BOOLEAN                     IsaSupported;
  EFI_EVENT                   Event;
  EFI_LOADED_IMAGE_PROTOCOL   *LoadedImage;

  Status = EfiGetSystemConfigurationTable (&gEfiDebugImageInfoTableGuid, (VOID **)&gDebugImageTableHeader);
  if (EFI_ERROR (Status)) {
    gDebugImageTableHeader = NULL;
  }

  Status = gBS->LocateHandleBuffer (
                  ByProtocol,
                  &gEfiDebugSupportProtocolGuid,
                  NULL,
                  &HandleCount,
                  &Handles
                  );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Debug Support Protocol not found\n"));

    return Status;
  }

  DebugSupport = NULL;
  IsaSupported = FALSE;
  do {
    HandleCount--;
    Status = gBS->HandleProtocol (
                    Handles[HandleCount],
                    &gEfiDebugSupportProtocolGuid,
                    (VOID **)&DebugSupport
                    );
    if (!EFI_ERROR (Status)) {
      if (CheckIsa (DebugSupport->Isa)) {
        // We found what we are looking for so break out of the loop
        IsaSupported = TRUE;
        break;
      }
    }
  } while (HandleCount > 0);

  FreePool (Handles);

  if (!IsaSupported) {
    DEBUG ((DEBUG_ERROR, "Debug Support Protocol does not support our ISA\n"));

    return EFI_NOT_FOUND;
  }

  MaxProcessorIndex = 0;
  Status = DebugSupport->GetMaximumProcessorIndex (DebugSupport, &MaxProcessorIndex);
  ASSERT_EFI_ERROR (Status);

  DEBUG ((DEBUG_INFO, "Debug Support Protocol ISA %x\n", DebugSupport->Isa));
  DEBUG ((DEBUG_INFO, "Debug Support Protocol Processor Index %d\n", MaxProcessorIndex));

  // Call processor-specific init routine
  InitializeProcessor ();

  for (Processor = 0; Processor <= MaxProcessorIndex; Processor++) {
    for (Index = 0; Index < MaxEfiException (); Index++) {
      Status = DebugSupport->RegisterExceptionCallback (DebugSupport, Processor, GdbExceptionHandler, gExceptionType[Index].Exception);
      ASSERT_EFI_ERROR (Status);
    }

    //
    // Current edk2 DebugPort is not interrupt context safe so we can not use it
    //
    Status = DebugSupport->RegisterPeriodicCallback (DebugSupport, Processor, GdbPeriodicCallBack);
    ASSERT_EFI_ERROR (Status);
  }

  Status = gBS->HandleProtocol (
                  ImageHandle,
                  &gEfiLoadedImageProtocolGuid,
                  (VOID**)&LoadedImage
                  );
  if (!EFI_ERROR (Status)) {
    gLoadedImageDebugPath = PeCoffLoaderGetDebuggerInfo (
                              LoadedImage->ImageBase,
                              &gLoadedImageBase,
                              &gLoadedImageCodeBase
                              );
  }

  if (PcdGet32 (PcdGdbDebugConfigFlags) & GDB_INITIAL_BREAK) {
    #if defined (__GNUC__) || defined (__clang__)
      __asm ("int3");
    #elif defined (_MSC_VER)
      __debugbreak();
    #endif
  }

  //
  // This even fires every time an image is added. This allows the stub to know when gdb needs
  // to update the symbol table.
  //
  Status = gBS->CreateEvent (
                  EVT_NOTIFY_SIGNAL,
                  TPL_CALLBACK,
                  GdbSymbolEventHandler,
                  NULL,
                  &Event
                  );
  ASSERT_EFI_ERROR (Status);
  //
  // Register for protocol notifications on this event
  //
  Status = gBS->RegisterProtocolNotify (
                  &gEfiLoadedImageProtocolGuid,
                  Event,
                  &gGdbSymbolEventHandlerRegistration
                  );
  ASSERT_EFI_ERROR (Status);

  if (PcdGetBool (PcdGdbSerialConsole)) {
    GdbInitializeSerialConsole ();
  }

  return EFI_SUCCESS;
}