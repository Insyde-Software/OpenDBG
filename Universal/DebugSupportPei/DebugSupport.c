/** @file
  Top level C file for debug support driver.  Contains initialization function.

  Copyright (c) 2024, Insyde Software Corp. All rights reserved.<BR>

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#pragma optimize ("", off)
#include <Pi/PiPeiCis.h>
#include <Ppi/DebugSupport.h>
#include "PlDebugSupport.h"
#include <Library/PeiServicesLib.h>

/**
  Debug Support Driver entry point.

  Checks to see if there's not already a Debug Support protocol installed for
  the selected processor before installing it.

  @param[in]  FileHandle   Pointer to image file handle.
  @param[in]  PeiServices  Pointer to PEI Services Table

  @retval EFI_SUCCESS          The entry point is executed successfully.
  @retval EFI_ALREADY_STARTED  Debug Support protocol is installed already.
  @retval other                Some error occurs when executing this entry point.

**/
EFI_STATUS
EFIAPI
InitializeDebugSupportDriver (
  IN EFI_PEI_FILE_HANDLE        FileHandle,
  IN CONST EFI_PEI_SERVICES     **PeiServices
  )
{
  EFI_STATUS                    Status;
  EFI_PEI_PPI_DESCRIPTOR        *DebugSupportPpiList;
  EFI_DEBUG_SUPPORT_PPI         *DebugSupportPpi;

  //
  // Call hook for processor specific initialization
  //
  Status = PlInitializeDebugSupportDriver ();
  ASSERT (!EFI_ERROR (Status));
  if (Status != EFI_SUCCESS) {
    return Status;
  }

  DebugSupportPpi = AllocateZeroPool (sizeof (EFI_DEBUG_SUPPORT_PPI));
  if (DebugSupportPpi == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  DebugSupportPpi->Isa                        = EFI_ISA;
  DebugSupportPpi->GetMaximumProcessorIndex   = GetMaximumProcessorIndex;
  DebugSupportPpi->RegisterPeriodicCallback   = RegisterPeriodicCallback;
  DebugSupportPpi->RegisterExceptionCallback  = RegisterExceptionCallback;
  DebugSupportPpi->InvalidateInstructionCache = InvalidateInstructionCache;

  DebugSupportPpiList = AllocateZeroPool (sizeof (EFI_PEI_PPI_DESCRIPTOR));
  if (DebugSupportPpiList == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  DebugSupportPpiList->Flags = (EFI_PEI_PPI_DESCRIPTOR_PPI | EFI_PEI_PPI_DESCRIPTOR_TERMINATE_LIST);
  DebugSupportPpiList->Guid  = &gEfiDebugSupportPpiGuid;
  DebugSupportPpiList->Ppi   = DebugSupportPpi;

  Status = PeiServicesInstallPpi (DebugSupportPpiList);
  if (EFI_ERROR (Status)) {
    return EFI_OUT_OF_RESOURCES;
  }

  return EFI_SUCCESS;
}