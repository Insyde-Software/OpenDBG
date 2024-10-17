/** @file
  UEFI driver that implements a GDB stub

  This is a GDB stub peim that which communicates with the debugger over
  a physical transport

  Copyright (c) 2024, Insyde Software Corp. All rights reserved.<BR>

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Pi/PiPeiCis.h>
#include <Guid/StatusCodeDataTypeId.h>
#include <Guid/StatusCodeDataTypeDebug.h>
#include <Library/PeiServicesLib.h>
#include <Library/ReportStatusCodeLib.h>
#include <Ppi/ReportStatusCodeHandler.h>
#include <Ppi/DebugSupport.h>
#include <Ppi/LoadFile.h>
#include "GdbStubInternal.h"

EFI_PEI_LOAD_FILE_PPI   gLoadFile;
EFI_PEI_PPI_DESCRIPTOR  gLoadFileDesc;
EFI_PEI_LOAD_FILE_PPI   *gPeiCoreLoadFile;
EFI_PEI_PPI_DESCRIPTOR  *gPeiCoreLoadFileDesc;

EFI_STATUS
EFIAPI
RscHandlerPpiNotifyCallback (
  IN EFI_PEI_SERVICES              **PeiServices,
  IN EFI_PEI_NOTIFY_DESCRIPTOR     *NotifyDescriptor,
  IN VOID                          *Ppi
  );

EFI_PEI_NOTIFY_DESCRIPTOR mNotifyOnRscHandlerPpiList = {
  (EFI_PEI_PPI_DESCRIPTOR_NOTIFY_CALLBACK | EFI_PEI_PPI_DESCRIPTOR_TERMINATE_LIST),
  &gEfiPeiRscHandlerPpiGuid,
  RscHandlerPpiNotifyCallback 
};


/**
  Convert status code value and extended data to readable ASCII string, send string to H2O DDT.

  @param  PeiServices      An indirect pointer to the EFI_PEI_SERVICES table published by the PEI Foundation.
  @param  CodeType         Indicates the type of status code being reported.
  @param  Value            Describes the current status of a hardware or
                           software entity. This includes information about the class and
                           subclass that is used to classify the entity as well as an operation.
                           For progress codes, the operation is the current activity.
                           For error codes, it is the exception.For debug codes,it is not defined at this time.
  @param  Instance         The enumeration of a hardware or software entity within
                           the system. A system may contain multiple entities that match a class/subclass
                           pairing. The instance differentiates between them. An instance of 0 indicates
                           that instance information is unavailable, not meaningful, or not relevant.
                           Valid instance numbers start with 1.
  @param  CallerId         This optional parameter may be used to identify the caller.
                           This parameter allows the status code driver to apply different rules to
                           different callers.
  @param  Data             This optional parameter may be used to pass additional data.

  @retval EFI_SUCCESS      Status code reported to H2O DDT successfully.

**/
EFI_STATUS
EFIAPI
StatusCodeReportWorker (
  IN CONST  EFI_PEI_SERVICES        **PeiServices,
  IN EFI_STATUS_CODE_TYPE           CodeType,
  IN EFI_STATUS_CODE_VALUE          Value,
  IN UINT32                         Instance,
  IN CONST EFI_GUID                 *CallerId,
  IN CONST EFI_STATUS_CODE_DATA     *Data OPTIONAL
  )
{
  CHAR8           *Filename;
  CHAR8           *Description;
  CHAR8           *Format;
  CHAR8           Buffer[EFI_STATUS_CODE_DATA_MAX_SIZE];
  UINT32          LineNumber;
  UINTN           CharCount;
  BASE_LIST       Marker;
  EFI_DEBUG_INFO  *DebugInfo;

  CharCount = 0;
  Buffer[0] = '\0';

  if (Data != NULL &&
      ReportStatusCodeExtractAssertInfo (CodeType, Value, Data, &Filename, &Description, &LineNumber)) {
    //
    // Print ASSERT() information into output buffer.
    //
    CharCount = AsciiSPrint (
                  Buffer,
                  sizeof (Buffer),
                  "\n\rPEI_ASSERT!: %a (%d): %a",
                  Filename,
                  LineNumber,
                  Description
                  );
  } else if (Data != NULL &&
             CompareGuid (&Data->Type, &gEfiStatusCodeDataTypeDebugGuid)) {
    //
    // Retrieve the debug information from the status code record
    //
    DebugInfo = (EFI_DEBUG_INFO *)(Data + 1);
    Marker = (BASE_LIST)(DebugInfo + 1);
    Format = (CHAR8 *)(((UINT64 *)*Marker) + 12);
    CharCount = AsciiBSPrint (
                  Buffer,
                  sizeof (Buffer),
                  Format,
                  Marker
                  );
  } else if ((CodeType & EFI_STATUS_CODE_TYPE_MASK) == EFI_ERROR_CODE) {
    //
    // Print ERROR information into output buffer.
    //
    CharCount = AsciiSPrint (
                  Buffer,
                  sizeof (Buffer),
                  "ERROR: C%x:V%x I%x",
                  CodeType,
                  Value,
                  Instance
                  );
    
    ASSERT(CharCount > 0);
    
    if (CallerId != NULL) {
      CharCount += AsciiSPrint (
                     &Buffer[CharCount],
                     (sizeof (Buffer) - (sizeof (Buffer[0]) * CharCount)),
                     " %g",
                     CallerId
                     );
    }

    if (Data != NULL) {
      CharCount += AsciiSPrint (
                     &Buffer[CharCount],
                     (sizeof (Buffer) - (sizeof (Buffer[0]) * CharCount)),
                     " %x",
                     Data
                     );
    }

  } else if ((CodeType & EFI_STATUS_CODE_TYPE_MASK) == EFI_PROGRESS_CODE) {
    //
    // Print PROGRESS information into output buffer.
    //
    CharCount = AsciiSPrint (
                  Buffer,
                  sizeof (Buffer),
                  "PROGRESS CODE: V%x I%x",
                  Value,
                  Instance
                  );
  } else if (Data != NULL &&
             CompareGuid (&Data->Type, &gEfiStatusCodeDataTypeStringGuid) &&
             ((EFI_STATUS_CODE_STRING_DATA *) Data)->StringType == EfiStringAscii) {
    //
    // EFI_STATUS_CODE_STRING_DATA
    //
    CharCount = AsciiSPrint (
                  Buffer,
                  sizeof (Buffer),
                  "%a",
                  ((EFI_STATUS_CODE_STRING_DATA *) Data)->String.Ascii
                  );
  } else {
    //
    // Code type is not defined.
    //
    CharCount = AsciiSPrint (
                  Buffer,
                  sizeof (Buffer),
                  "Undefined: C%x:V%x I%x",
                  CodeType,
                  Value,
                  Instance
                  );
  }

  //
  // Call OutputDebugString function to do print.
  //
  if (CharCount > 0) {
    Buffer[CharCount ++] = 0x0d;
    Buffer[CharCount ++] = 0x0a;
    Buffer[CharCount ++] = 0;
    OutputDebugString ((CHAR8 *) Buffer);
  }

  return EFI_SUCCESS;
}

/**
  Notification service to be called when gEfiPeiRscHandlerPpiGuid is installed.

  @param  PeiServices           Indirect reference to the PEI Services Table.
  @param  NotifyDescriptor      Address of the notification descriptor data structure. Type
                                EFI_PEI_NOTIFY_DESCRIPTOR is defined above.
  @param  Ppi                   Address of the PPI that was installed.

  @retval EFI_STATUS            This function will install a PPI to PPI database. The status
                                code will be the code for (*PeiServices)->InstallPpi.

**/
EFI_STATUS
EFIAPI
RscHandlerPpiNotifyCallback (
  IN EFI_PEI_SERVICES              **PeiServices,
  IN EFI_PEI_NOTIFY_DESCRIPTOR     *NotifyDescriptor,
  IN VOID                          *Ppi
  )
{
  EFI_STATUS                  Status;
  EFI_PEI_RSC_HANDLER_PPI     *RscHandlerPpi;

  Status = PeiServicesLocatePpi (
             &gEfiPeiRscHandlerPpiGuid,
             0,
             NULL,
             (VOID **) &RscHandlerPpi
             );

  if (!EFI_ERROR(Status)) {
    //
    // Dispatch initialization request to sub-statuscode-devices.
    //
    Status = RscHandlerPpi->Register (StatusCodeReportWorker);
  } 
  ASSERT_EFI_ERROR (Status);

  return Status;
}

/**
  Loads a PEIM into memory for subsequent execution.

  This service is the single member function of EFI_LOAD_FILE_PPI.
  This service separates image loading and relocating from the PEI Foundation.

  @param This                   Interface pointer that implements
                                the Load File PPI instance.
  @param FileHandle             File handle of the file to load.
  @param ImageAddress           Pointer to the address of the loaded image.
  @param ImageSize              Pointer to the size of the loaded image.
  @param EntryPoint             Pointer to the entry point of the image.
  @param AuthenticationState    On exit, points to the attestation
                                authentication state of the image
                                or 0 if no attestation was performed.

  @retval EFI_SUCCESS           The image was loaded successfully.
  @retval EFI_OUT_OF_RESOURCES  There was not enough memory.
  @retval EFI_LOAD_ERROR        There was no supported image in the file.
  @retval EFI_INVALID_PARAMETER FileHandle was not a valid firmware file handle.
  @retval EFI_INVALID_PARAMETER EntryPoint was NULL.
  @retval EFI_UNSUPPORTED       An image requires relocations or is not
                                memory mapped.
  @retval EFI_WARN_BUFFER_TOO_SMALL
                                There is not enough heap to allocate the requested size.
                                This will not prevent the XIP image from being invoked.

**/
STATIC
EFI_STATUS
EFIAPI
LoadFile (
  IN  CONST EFI_PEI_LOAD_FILE_PPI       *This,
  IN  EFI_PEI_FILE_HANDLE               FileHandle,
  OUT EFI_PHYSICAL_ADDRESS              *ImageAddress,
  OUT UINT64                            *ImageSize,
  OUT EFI_PHYSICAL_ADDRESS              *EntryPoint,
  OUT UINT32                            *AuthenticationState
  )
{
  EFI_STATUS    Status;
  UINTN         Index;
  UINTN         End;
  CHAR8         StringBuffer[0x100];

  Status = gPeiCoreLoadFile->LoadFile (
                               gPeiCoreLoadFile,
                               FileHandle,
                               ImageAddress,
                               ImageSize,
                               EntryPoint,
                               AuthenticationState
                               );
  if (!EFI_ERROR (Status)) {
    gLoadedImageDebugPath = PeCoffLoaderGetDebuggerInfo (
                              (VOID*)(UINTN)(*ImageAddress),
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
        AsciiSPrint (StringBuffer, 0x100, "[PEI] %a", &gLoadedImageDebugPath[Index]);
        AsciiSPrint (&StringBuffer[6 + (End - Index)], 0x100, ".efi at 0x%012X\n\r", gLoadedImageBase);
        OutputDebugString (StringBuffer);
      }
    }
  }
  return Status;
}

/**
  Prints a formatted Unicode string to the console output device specified by
  ConOut defined in the EFI_SYSTEM_TABLE.

  This function prints a formatted Unicode string to the console output device
  specified by ConOut in EFI_SYSTEM_TABLE and returns the number of Unicode
  characters that printed to ConOut.  If the length of the formatted Unicode
  string is greater than PcdUefiLibMaxPrintBufferSize, then only the first
  PcdUefiLibMaxPrintBufferSize characters are sent to ConOut.
  If Format is NULL, then ASSERT().
  If Format is not aligned on a 16-bit boundary, then ASSERT().
  If gST->ConOut is NULL, then ASSERT().

  @param Format   A Null-terminated Unicode format string.
  @param ...      A Variable argument list whose contents are accessed based
                  on the format string specified by Format.

  @return The number of Unicode characters printed to ConOut.

**/
UINTN
EFIAPI
Print (
  IN CONST CHAR16  *Format,
  ...
  )
{
  return 0;
}

/**
  The user Entry Point for Application. The user code starts with this function
  as the real entry point for the image goes into a library that calls this
  function.

  @param[in]  FileHandle   Pointer to image file handle.
  @param[in]  PeiServices  Pointer to PEI Services Table

  @retval EFI_SUCCESS       The entry point is executed successfully.
  @retval other             Some error occurs when executing this entry point.

**/
EFI_STATUS
EFIAPI
GdbStubPeiEntry (
  IN EFI_PEI_FILE_HANDLE        FileHandle,
  IN CONST EFI_PEI_SERVICES     **PeiServices
  )
{
  EFI_STATUS                    Status;
  EFI_DEBUG_SUPPORT_PPI         *DebugSupport;
  EFI_PEI_RSC_HANDLER_PPI       *RscHandlerPpi;
  UINTN                         MaxProcessorIndex;
  UINTN                         Index;
  UINTN                         Processor;
  BOOLEAN                       IsaSupported;

  Index        = 0;
  IsaSupported = FALSE;
  while (TRUE) {
    Status = PeiServicesLocatePpi (
               &gEfiDebugSupportPpiGuid,
               Index,
               NULL,
               (VOID **)&DebugSupport
               );
    if (EFI_ERROR (Status)) {
      return Status;
    }

    if (CheckIsa (DebugSupport->Isa)) {
      // We found what we are looking for so break out of the loop
      IsaSupported = TRUE;
      break;
    }

    Index++;
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

  //
  // Install PeiLoadFilePpi for loading symbol info 
  //
  Status = PeiServicesLocatePpi (
             &gEfiPeiLoadFilePpiGuid,
             0,
             &gPeiCoreLoadFileDesc,
             (VOID**)&gPeiCoreLoadFile
             );
  if (!EFI_ERROR (Status)) {
    gLoadFile.LoadFile  = LoadFile;
    gLoadFileDesc.Flags = (EFI_PEI_PPI_DESCRIPTOR_PPI | EFI_PEI_PPI_DESCRIPTOR_TERMINATE_LIST);
    gLoadFileDesc.Guid  = &gEfiPeiLoadFilePpiGuid;
    gLoadFileDesc.Ppi   = &gLoadFile;
    Status = PeiServicesReInstallPpi (
               gPeiCoreLoadFileDesc,
               &gLoadFileDesc
               );
  }

  if (PcdGet32 (PcdGdbDebugConfigFlags) & GDB_DEBUG_LOG_ENABLED) {
    Status = PeiServicesLocatePpi (
               &gEfiPeiRscHandlerPpiGuid,
               0,
               NULL,
               (VOID **) &RscHandlerPpi
               );
    if (EFI_ERROR (Status)) {
      PeiServicesNotifyPpi (&mNotifyOnRscHandlerPpiList);
    } else {
      Status = RscHandlerPpi->Register (StatusCodeReportWorker);
    }
  }

  if (PcdGet32 (PcdGdbDebugConfigFlags) & GDB_INITIAL_BREAK) {
    #if defined (__GNUC__) || defined (__clang__)
      __asm ("int3");
    #elif defined (_MSC_VER)
      __debugbreak();
    #endif
  }

  return EFI_SUCCESS;
}