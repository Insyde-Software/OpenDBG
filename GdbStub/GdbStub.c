/** @file
  UEFI driver that implements a GDB stub

  This is a GDB stub driver that which communicates with the debugger over
  a physical transport

  Copyright (c) 2008 - 2009, Apple Inc. All rights reserved.<BR>
  Copyright (c) 2024, Insyde Software Corp. All rights reserved.<BR>

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <GdbStubInternal.h>

//
// Buffers for basic gdb communication
//
CHAR8  gInBuffer[MAX_BUF_SIZE];
CHAR8  gOutBuffer[MAX_BUF_SIZE];

// Assume gdb does a "qXfer:libraries:read::offset,length" when it connects so we can default
// this value to FALSE. Since gdb can reconnect its self a global default is not good enough
BOOLEAN    gSymbolTableUpdate = FALSE;

//
// Set TRUE if F Reply package signals a ctrl-c. We can not process the Ctrl-c
// here we need to wait for the periodic callback to do this.
//
BOOLEAN  gCtrlCBreakFlag = FALSE;

//
// If the periodic callback is called while we are processing an F packet we need
// to let the callback know to not read from the serial stream as it could steal
// characters from the F response packet
//
BOOLEAN  gProcessingFPacket = FALSE;//
// Globals for returning XML from qXfer:libraries:read packet
//
UINTN                              gPacketqXferLibraryOffset = 0;
UINTN                              gEfiDebugImageTableEntry  = 0;
EFI_DEBUG_IMAGE_INFO_TABLE_HEADER  *gDebugImageTableHeader   = NULL;
EFI_DEBUG_IMAGE_INFO               *gDebugTable              = NULL;
CHAR8                              gXferLibraryBuffer[MAX_BUF_SIZE];

VOID                               *gLoadedImageBase         = NULL;
VOID                               *gLoadedImageCodeBase     = NULL;
CHAR8                              *gLoadedImageDebugPath    = NULL;

GLOBAL_REMOVE_IF_UNREFERENCED CONST CHAR8  mHexToStr[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

/**
 Transfer length bytes of input buffer, starting at Address, to memory.

 @param     length                  the number of the bytes to be transferred/written
 @param     *address                the start address of the transferring/writing the memory
 @param     *new_data               the new data to be written to memory
 **/
VOID
TransferFromInBufToMem (
  IN    UINTN          Length,
  IN    unsigned char  *Address,
  IN    CHAR8          *NewData
  )
{
  CHAR8  c1;
  CHAR8  c2;

  while (Length-- > 0) {
    c1 = (CHAR8)HexCharToInt (*NewData++);
    c2 = (CHAR8)HexCharToInt (*NewData++);

    if ((c1 < 0) || (c2 < 0)) {
      Print ((CHAR16 *)L"Bad message from write to memory..\n");
      SendError (GDB_EBADMEMDATA);
      return;
    }

    *Address++ = (UINT8)((c1 << 4) + c2);
  }

  SendSuccess ();
}

/**
 Transfer Length bytes of memory starting at Address to an output buffer, OutBuffer. This function will finally send the buffer
 as a packet.

 @param     Length                  the number of the bytes to be transferred/read
 @param     *address                pointer to the start address of the transferring/reading the memory
 **/
VOID
TransferFromMemToOutBufAndSend (
  IN    UINTN          Length,
  IN    unsigned char  *Address
  )
{
  // there are Length bytes and every byte is represented as 2 hex chars
  CHAR8  *OutBufPtr;              // pointer to the output buffer
  CHAR8  Char;

  if (ValidateAddress (Address) == FALSE) {
    SendError (14);
    return;
  }

  OutBufPtr = gOutBuffer;
  while (Length > 0) {
    Char = mHexToStr[*Address >> 4];
    if ((Char >= 'A') && (Char <= 'F')) {
      Char = Char - 'A' + 'a';
    }

    *OutBufPtr++ = Char;

    Char = mHexToStr[*Address & 0x0f];
    if ((Char >= 'A') && (Char <= 'F')) {
      Char = Char - 'A' + 'a';
    }

    *OutBufPtr++ = Char;

    Address++;
    Length--;
  }

  *OutBufPtr = '\0';   // the end of the buffer
  SendPacket (gOutBuffer);
}

/**
  Send a GDB Remote Serial Protocol Packet

  $PacketData#checksum PacketData is passed in and this function adds the packet prefix '$',
  the packet terminating character '#' and the two digit checksum.

  If an ack '+' is not sent resend the packet, but timeout eventually so we don't end up
  in an infinite loop. This is so if you unplug the debugger code just keeps running

  @param PacketData   Payload data for the packet


  @retval             Number of bytes of packet data sent.

**/
UINTN
SendPacket (
  IN  CHAR8  *PacketData
  )
{
  UINT8  CheckSum;
  UINTN  Timeout;
  CHAR8  *Ptr;
  CHAR8  TestChar;
  UINTN  Count;

  Timeout = PcdGet32 (PcdGdbMaxPacketRetryCount);

  Count = 0;
  do {
    Ptr = PacketData;

    if (Timeout-- == 0) {
      // Only try a finite number of times so we don't get stuck in the loop
      return Count;
    }

    // Packet prefix
    GdbPutChar ('$');

    for (CheckSum = 0, Count = 0; *Ptr != '\0'; Ptr++, Count++) {
      GdbPutChar (*Ptr);
      CheckSum = CheckSum + *Ptr;
    }

    // Packet terminating character and checksum
    GdbPutChar ('#');
    GdbPutChar (mHexToStr[CheckSum >> 4]);
    GdbPutChar (mHexToStr[CheckSum & 0x0F]);

    TestChar =  GdbGetChar ();
  } while (TestChar != '+');

  return Count;
}

/**
  Receive a GDB Remote Serial Protocol Packet

  $PacketData#checksum PacketData is passed in and this function adds the packet prefix '$',
  the packet terminating character '#' and the two digit checksum.

  If host re-starts sending a packet without ending the previous packet, only the last valid packet is processed.
  (In other words, if received packet is '$12345$12345$123456#checksum', only '$123456#checksum' will be processed.)

  If an ack '+' is not sent resend the packet

  @param PacketData   Payload data for the packet

  @retval             Number of bytes of packet data received.

**/
UINTN
ReceivePacket (
  OUT  CHAR8  *PacketData,
  IN   UINTN  PacketDataSize
  )
{
  UINT8  CheckSum;
  UINTN  Index;
  CHAR8  Char;
  CHAR8  SumString[3];
  CHAR8  TestChar;

  ZeroMem (PacketData, PacketDataSize);

  for ( ; ;) {
    // wait for the start of a packet
    TestChar = GdbGetChar ();
    while (TestChar != '$') {
      TestChar = GdbGetChar ();
    }

retry:
    for (Index = 0, CheckSum = 0; Index < (PacketDataSize - 1); Index++) {
      Char = GdbGetChar ();
      if (Char == '$') {
        goto retry;
      }

      if (Char == '#') {
        break;
      }

      PacketData[Index] = Char;
      CheckSum          = CheckSum + Char;
    }

    PacketData[Index] = '\0';

    if (Index == PacketDataSize) {
      continue;
    }

    SumString[0] = GdbGetChar ();
    SumString[1] = GdbGetChar ();
    SumString[2] = '\0';

    if (AsciiStrHexToUintn (SumString) == CheckSum) {
      // Ack: Success
      GdbPutChar ('+');

      // Null terminate the callers string
      PacketData[Index] = '\0';
      return Index;
    } else {
      // Ack: Failure
      GdbPutChar ('-');
    }
  }

  // return 0;
}

/**
 Empties the given buffer
 @param   Buf          pointer to the first element in buffer to be emptied
 **/
VOID
EmptyBuffer (
  IN  CHAR8  *Buf
  )
{
  *Buf = '\0';
}

/**
 Converts an 8-bit Hex Char into a INTN.

 @param   Char the hex character to be converted into UINTN
 @retval  a INTN, from 0 to 15, that corresponds to Char
 -1 if Char is not a hex character
 **/
INTN
HexCharToInt (
  IN  CHAR8  Char
  )
{
  if ((Char >= 'A') && (Char <= 'F')) {
    return Char - 'A' + 10;
  } else if ((Char >= 'a') && (Char <= 'f')) {
    return Char - 'a' + 10;
  } else if ((Char >= '0') && (Char <= '9')) {
    return Char - '0';
  } else {
    // if not a hex value, return a negative value
    return -1;
  }
}

// 'E' + the biggest error number is 255, so its 2 hex digits + buffer end
CHAR8  *gError = "E__";

/** 'E NN'
 Send an error with the given error number after converting to hex.
 The error number is put into the buffer in hex. '255' is the biggest errno we can send.
 ex: 162 will be sent as A2.

 @param   errno           the error number that will be sent
 **/
VOID
EFIAPI
SendError (
  IN  UINT8  ErrorNum
  )
{
  //
  // Replace _, or old data, with current errno
  //
  gError[1] = mHexToStr[ErrorNum >> 4];
  gError[2] = mHexToStr[ErrorNum & 0x0f];

  SendPacket (gError); // send buffer
}

/**
 Send 'OK' when the function is done executing successfully.
 **/
VOID
EFIAPI
SendSuccess (
  VOID
  )
{
  SendPacket ("OK"); // send buffer
}

/**
 Send empty packet to specify that particular command/functionality is not supported.
 **/
VOID
EFIAPI
SendNotSupported (
  VOID
  )
{
  SendPacket ("");
}

/**
 Send the T signal with the given exception type (in gdb order) and possibly with n:r pairs related to the watchpoints

 @param  SystemContext        Register content at time of the exception
 @param  GdbExceptionType     GDB exception type
 **/
VOID
GdbSendTSignal (
  IN  EFI_SYSTEM_CONTEXT  SystemContext,
  IN  UINT8               GdbExceptionType
  )
{
  CHAR8       TSignalBuffer[128];
  CHAR8       *TSignalPtr;
  UINTN       BreakpointDetected;
  BREAK_TYPE  BreakType;
  UINTN       DataAddress;
  CHAR8       *WatchStrPtr = NULL;
  UINTN       RegSize;

  TSignalPtr = &TSignalBuffer[0];

  // Construct TSignal packet
  *TSignalPtr++ = 'T';

  //
  // replace _, or previous value, with Exception type
  //
  *TSignalPtr++ = mHexToStr[GdbExceptionType >> 4];
  *TSignalPtr++ = mHexToStr[GdbExceptionType & 0x0f];

  if (GdbExceptionType == GDB_SIGTRAP) {
    if (gSymbolTableUpdate) {
      //
      // We can only send back on reason code. So if the flag is set it means the breakpoint is from our event handler
      //
      WatchStrPtr = "library:;";
      while (*WatchStrPtr != '\0') {
        *TSignalPtr++ = *WatchStrPtr++;
      }

      gSymbolTableUpdate = FALSE;
    } else {
      //
      // possible n:r pairs
      //

      // Retrieve the breakpoint number
      BreakpointDetected = GetBreakpointDetected (SystemContext);

      // Figure out if the exception is happend due to watch, rwatch or awatch.
      BreakType = GetBreakpointType (SystemContext, BreakpointDetected);

      // INFO: rwatch is not supported due to the way IA32 debug registers work
      if ((BreakType == DataWrite) || (BreakType == DataRead) || (BreakType == DataReadWrite)) {
        // Construct n:r pair
        DataAddress = GetBreakpointDataAddress (SystemContext, BreakpointDetected);

        // Assign appropriate buffer to print particular watchpoint type
        if (BreakType == DataWrite) {
          WatchStrPtr = "watch";
        } else if (BreakType == DataRead) {
          WatchStrPtr = "rwatch";
        } else if (BreakType == DataReadWrite) {
          WatchStrPtr = "awatch";
        }

        while (*WatchStrPtr != '\0') {
          *TSignalPtr++ = *WatchStrPtr++;
        }

        *TSignalPtr++ = ':';

        // Set up series of bytes in big-endian byte order. "awatch" won't work with little-endian byte order.
        RegSize = REG_SIZE;
        while (RegSize > 0) {
          RegSize       = RegSize-4;
          *TSignalPtr++ = mHexToStr[(UINT8)(DataAddress >> RegSize) & 0xf];
        }

        // Always end n:r pair with ';'
        *TSignalPtr++ = ';';
      }
    }
  }

  *TSignalPtr = '\0';

  SendPacket (TSignalBuffer);
}

/**
 Translates the EFI mapping to GDB mapping

 @param   EFIExceptionType    EFI Exception that is being processed
 @retval  UINTN that corresponds to EFIExceptionType's GDB exception type number
 **/
UINT8
ConvertEFItoGDBtype (
  IN  EFI_EXCEPTION_TYPE  EFIExceptionType
  )
{
  UINTN  Index;

  for (Index = 0; Index < MaxEfiException (); Index++) {
    if (gExceptionType[Index].Exception == EFIExceptionType) {
      return gExceptionType[Index].SignalNo;
    }
  }

  return GDB_SIGTRAP; // this is a GDB trap
}

/** "m addr,length"
 Find the Length of the area to read and the start address. Finally, pass them to
 another function, TransferFromMemToOutBufAndSend, that will read from that memory space and
 send it as a packet.
 **/
VOID
EFIAPI
ReadFromMemory (
  CHAR8  *PacketData
  )
{
  UINTN  Address;
  UINTN  Length;
  CHAR8  AddressBuffer[MAX_ADDR_SIZE]; // the buffer that will hold the address in hex chars
  CHAR8  *AddrBufPtr;                  // pointer to the address buffer
  CHAR8  *InBufPtr;                    /// pointer to the input buffer

  AddrBufPtr = AddressBuffer;
  InBufPtr   = &PacketData[1];
  while (*InBufPtr != ',') {
    *AddrBufPtr++ = *InBufPtr++;
  }

  *AddrBufPtr = '\0';

  InBufPtr++; // this skips ',' in the buffer

  /* Error checking */
  if (AsciiStrLen (AddressBuffer) >= MAX_ADDR_SIZE) {
    Print ((CHAR16 *)L"Address is too long\n");
    SendError (GDB_EBADMEMADDRBUFSIZE);
    return;
  }

  // 2 = 'm' + ','
  if (AsciiStrLen (PacketData) - AsciiStrLen (AddressBuffer) - 2 >= MAX_LENGTH_SIZE) {
    Print ((CHAR16 *)L"Length is too long\n");
    SendError (GDB_EBADMEMLENGTH);
    return;
  }

  Address = AsciiStrHexToUintn (AddressBuffer);
  Length  = AsciiStrHexToUintn (InBufPtr);

  TransferFromMemToOutBufAndSend (Length, (unsigned char *)Address);
}

/** "M addr,length :XX..."
 Find the Length of the area in bytes to write and the start address. Finally, pass them to
 another function, TransferFromInBufToMem, that will write to that memory space the info in
 the input buffer.
 **/
VOID
EFIAPI
WriteToMemory (
  IN CHAR8  *PacketData
  )
{
  UINTN  Address;
  UINTN  Length;
  UINTN  MessageLength;
  CHAR8  AddressBuffer[MAX_ADDR_SIZE];  // the buffer that will hold the Address in hex chars
  CHAR8  LengthBuffer[MAX_LENGTH_SIZE]; // the buffer that will hold the Length in hex chars
  CHAR8  *AddrBufPtr;                   // pointer to the Address buffer
  CHAR8  *LengthBufPtr;                 // pointer to the Length buffer
  CHAR8  *InBufPtr;                     /// pointer to the input buffer

  AddrBufPtr   = AddressBuffer;
  LengthBufPtr = LengthBuffer;
  InBufPtr     = &PacketData[1];

  while (*InBufPtr != ',') {
    *AddrBufPtr++ = *InBufPtr++;
  }

  *AddrBufPtr = '\0';

  InBufPtr++; // this skips ',' in the buffer

  while (*InBufPtr != ':') {
    *LengthBufPtr++ = *InBufPtr++;
  }

  *LengthBufPtr = '\0';

  InBufPtr++; // this skips ':' in the buffer

  Address = AsciiStrHexToUintn (AddressBuffer);
  Length  = AsciiStrHexToUintn (LengthBuffer);

  /* Error checking */

  // Check if Address is not too long.
  if (AsciiStrLen (AddressBuffer) >= MAX_ADDR_SIZE) {
    Print ((CHAR16 *)L"Address too long..\n");
    SendError (GDB_EBADMEMADDRBUFSIZE);
    return;
  }

  // Check if message length is not too long
  if (AsciiStrLen (LengthBuffer) >= MAX_LENGTH_SIZE) {
    Print ((CHAR16 *)L"Length too long..\n");
    SendError (GDB_EBADMEMLENGBUFSIZE);
    return;
  }

  // Check if Message is not too long/short.
  // 3 = 'M' + ',' + ':'
  MessageLength = (AsciiStrLen (PacketData) - AsciiStrLen (AddressBuffer) - AsciiStrLen (LengthBuffer) - 3);
  if (MessageLength != (2*Length)) {
    // Message too long/short. New data is not the right size.
    SendError (GDB_EBADMEMDATASIZE);
    return;
  }

  TransferFromInBufToMem (Length, (unsigned char *)Address, InBufPtr);
}

/**
  Parses breakpoint packet data and captures Breakpoint type, Address and length.
  In case of an error, function returns particular error code. Returning 0 meaning
  no error.

  @param  PacketData  Pointer to the payload data for the packet.
  @param  Type        Breakpoint type
  @param  Address     Breakpoint address
  @param  Length      Breakpoint length in Bytes (1 byte, 2 byte, 4 byte)

  @retval 1           Success
  @retval {other}     Particular error code

**/
UINTN
ParseBreakpointPacket (
  IN  CHAR8  *PacketData,
  OUT UINTN  *Type,
  OUT UINTN  *Address,
  OUT UINTN  *Length
  )
{
  CHAR8  AddressBuffer[MAX_ADDR_SIZE];
  CHAR8  *AddressBufferPtr;
  CHAR8  *PacketDataPtr;

  PacketDataPtr    = &PacketData[1];
  AddressBufferPtr = AddressBuffer;

  *Type = AsciiStrHexToUintn (PacketDataPtr);

  // Breakpoint/watchpoint type should be between 0 to 4
  if (*Type > 4) {
    Print ((CHAR16 *)L"Type is invalid\n");
    return 22; // EINVAL: Invalid argument.
  }

  // Skip ',' in the buffer.
  while (*PacketDataPtr++ != ',') {
  }

  // Parse Address information
  while (*PacketDataPtr != ',') {
    *AddressBufferPtr++ = *PacketDataPtr++;
  }

  *AddressBufferPtr = '\0';

  // Check if Address is not too long.
  if (AsciiStrLen (AddressBuffer) >= MAX_ADDR_SIZE) {
    Print ((CHAR16 *)L"Address too long..\n");
    return 40; // EMSGSIZE: Message size too long.
  }

  *Address = AsciiStrHexToUintn (AddressBuffer);

  PacketDataPtr++; // This skips , in the buffer

  // Parse Length information
  *Length = AsciiStrHexToUintn (PacketDataPtr);

  // Length should be 1, 2 or 4 bytes
  if (*Length > 4) {
    Print ((CHAR16 *)L"Length is invalid\n");
    return 22; // EINVAL: Invalid argument
  }

  return 0; // 0 = No error
}

UINTN
gXferObjectReadResponse (
  IN  CHAR8  Type,
  IN  CHAR8  *Str
  )
{
  CHAR8  *OutBufPtr;              // pointer to the output buffer
  CHAR8  Char;
  UINTN  Count;

  // Response starts with 'm' or 'l' if it is the end
  OutBufPtr    = gOutBuffer;
  *OutBufPtr++ = Type;
  Count        = 1;

  // Binary data encoding
  OutBufPtr = gOutBuffer;
  while (*Str != '\0') {
    Char = *Str++;
    if ((Char == 0x7d) || (Char == 0x23) || (Char == 0x24) || (Char == 0x2a)) {
      // escape character
      *OutBufPtr++ = 0x7d;

      Char ^= 0x20;
    }

    *OutBufPtr++ = Char;
    Count++;
  }

  *OutBufPtr = '\0';   // the end of the buffer
  SendPacket (gOutBuffer);

  return Count;
}

/**
  Note: This should be a library function.  In the Apple case you have to add
  the size of the PE/COFF header into the starting address to make things work
  right as there is no way to pad the Mach-O for the size of the PE/COFF header.


  Returns a pointer to the PDB file name for a PE/COFF image that has been
  loaded into system memory with the PE/COFF Loader Library functions.

  Returns the PDB file name for the PE/COFF image specified by Pe32Data.  If
  the PE/COFF image specified by Pe32Data is not a valid, then NULL is
  returned.  If the PE/COFF image specified by Pe32Data does not contain a
  debug directory entry, then NULL is returned.  If the debug directory entry
  in the PE/COFF image specified by Pe32Data does not contain a PDB file name,
  then NULL is returned.
  If Pe32Data is NULL, then ASSERT().

  @param  Pe32Data   Pointer to the PE/COFF image that is loaded in system
                     memory.
  @param  DebugBase  Address that the debugger would use as the base of the image

  @return The PDB file name for the PE/COFF image specified by Pe32Data or NULL
          if it cannot be retrieved. DebugBase is only valid if PDB file name is
          valid.

**/
VOID *
EFIAPI
PeCoffLoaderGetDebuggerInfo (
  IN VOID   *Pe32Data,
  OUT VOID  **DebugBase,
  OUT VOID  **CodeBase
  )
{
  EFI_IMAGE_DOS_HEADER                 *DosHdr;
  EFI_IMAGE_OPTIONAL_HEADER_PTR_UNION  Hdr;
  EFI_IMAGE_DATA_DIRECTORY             *DirectoryEntry;
  EFI_IMAGE_DEBUG_DIRECTORY_ENTRY      *DebugEntry;
  UINTN                                DirCount;
  VOID                                 *CodeViewEntryPointer;
  INTN                                 TEImageAdjust;
  UINT32                               NumberOfRvaAndSizes;
  UINT16                               Magic;
  UINTN                                SizeOfHeaders;

  ASSERT (Pe32Data   != NULL);

  TEImageAdjust       = 0;
  DirectoryEntry      = NULL;
  DebugEntry          = NULL;
  NumberOfRvaAndSizes = 0;
  SizeOfHeaders       = 0;

  DosHdr = (EFI_IMAGE_DOS_HEADER *)Pe32Data;
  if (DosHdr->e_magic == EFI_IMAGE_DOS_SIGNATURE) {
    //
    // DOS image header is present, so read the PE header after the DOS image header.
    //
    Hdr.Pe32 = (EFI_IMAGE_NT_HEADERS32 *)((UINTN)Pe32Data + (UINTN)((DosHdr->e_lfanew) & 0x0ffff));
  } else {
    //
    // DOS image header is not present, so PE header is at the image base.
    //
    Hdr.Pe32 = (EFI_IMAGE_NT_HEADERS32 *)Pe32Data;
  }

  if (Hdr.Te->Signature == EFI_TE_IMAGE_HEADER_SIGNATURE) {
    if (Hdr.Te->DataDirectory[EFI_TE_IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress != 0) {
      DirectoryEntry = &Hdr.Te->DataDirectory[EFI_TE_IMAGE_DIRECTORY_ENTRY_DEBUG];
      TEImageAdjust  = sizeof (EFI_TE_IMAGE_HEADER) - Hdr.Te->StrippedSize;
      DebugEntry     = (EFI_IMAGE_DEBUG_DIRECTORY_ENTRY *)((UINTN)Hdr.Te +
                                                           Hdr.Te->DataDirectory[EFI_TE_IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress +
                                                           TEImageAdjust);
    }

    SizeOfHeaders = sizeof (EFI_TE_IMAGE_HEADER) + (UINTN)Hdr.Te->BaseOfCode - (UINTN)Hdr.Te->StrippedSize;

    // __APPLE__ check this math...
    *DebugBase = ((CHAR8 *)Pe32Data) -  TEImageAdjust;
    if (CodeBase) *CodeBase = ((UINT8*)Pe32Data) + Hdr.Te->BaseOfCode;
  } else if (Hdr.Pe32->Signature == EFI_IMAGE_NT_SIGNATURE) {
    *DebugBase = Pe32Data;

    //
    // NOTE: We use Machine field to identify PE32/PE32+, instead of Magic.
    //       It is due to backward-compatibility, for some system might
    //       generate PE32+ image with PE32 Magic.
    //
    switch (Hdr.Pe32->FileHeader.Machine) {
      case EFI_IMAGE_MACHINE_IA32:
        //
        // Assume PE32 image with IA32 Machine field.
        //
        Magic = EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC;
        break;
      case EFI_IMAGE_MACHINE_X64:
      case EFI_IMAGE_MACHINE_IA64:
        //
        // Assume PE32+ image with X64 or IPF Machine field
        //
        Magic = EFI_IMAGE_NT_OPTIONAL_HDR64_MAGIC;
        break;
      default:
        //
        // For unknown Machine field, use Magic in optional Header
        //
        Magic = Hdr.Pe32->OptionalHeader.Magic;
    }

    if (Magic == EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
      //
      // Use PE32 offset get Debug Directory Entry
      //
      SizeOfHeaders       = Hdr.Pe32->OptionalHeader.SizeOfHeaders;
      NumberOfRvaAndSizes = Hdr.Pe32->OptionalHeader.NumberOfRvaAndSizes;
      DirectoryEntry      = (EFI_IMAGE_DATA_DIRECTORY *)&(Hdr.Pe32->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_DEBUG]);
      DebugEntry          = (EFI_IMAGE_DEBUG_DIRECTORY_ENTRY *)((UINTN)Pe32Data + DirectoryEntry->VirtualAddress);
      if (CodeBase) *CodeBase = ((UINT8*)Pe32Data) + Hdr.Pe32->OptionalHeader.BaseOfCode;
    } else if (Hdr.Pe32->OptionalHeader.Magic == EFI_IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
      //
      // Use PE32+ offset get Debug Directory Entry
      //
      SizeOfHeaders       = Hdr.Pe32Plus->OptionalHeader.SizeOfHeaders;
      NumberOfRvaAndSizes = Hdr.Pe32Plus->OptionalHeader.NumberOfRvaAndSizes;
      DirectoryEntry      = (EFI_IMAGE_DATA_DIRECTORY *)&(Hdr.Pe32Plus->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_DEBUG]);
      DebugEntry          = (EFI_IMAGE_DEBUG_DIRECTORY_ENTRY *)((UINTN)Pe32Data + DirectoryEntry->VirtualAddress);
      if (CodeBase) *CodeBase = ((UINT8*)Pe32Data) + Hdr.Pe32Plus->OptionalHeader.BaseOfCode;
    }

    if (NumberOfRvaAndSizes <= EFI_IMAGE_DIRECTORY_ENTRY_DEBUG) {
      DirectoryEntry = NULL;
      DebugEntry     = NULL;
    }
  } else {
    return NULL;
  }

  if ((DebugEntry == NULL) || (DirectoryEntry == NULL)) {
    return NULL;
  }

  for (DirCount = 0; DirCount < DirectoryEntry->Size; DirCount += sizeof (EFI_IMAGE_DEBUG_DIRECTORY_ENTRY), DebugEntry++) {
    if (DebugEntry->Type == EFI_IMAGE_DEBUG_TYPE_CODEVIEW) {
      if (DebugEntry->SizeOfData > 0) {
        CodeViewEntryPointer = (VOID *)((UINTN)DebugEntry->RVA + ((UINTN)Pe32Data) + (UINTN)TEImageAdjust);
        switch (*(UINT32 *)CodeViewEntryPointer) {
          case CODEVIEW_SIGNATURE_NB10:
            return (VOID *)((CHAR8 *)CodeViewEntryPointer + sizeof (EFI_IMAGE_DEBUG_CODEVIEW_NB10_ENTRY));
          case CODEVIEW_SIGNATURE_RSDS:
            return (VOID *)((CHAR8 *)CodeViewEntryPointer + sizeof (EFI_IMAGE_DEBUG_CODEVIEW_RSDS_ENTRY));
          case CODEVIEW_SIGNATURE_MTOC:
            *DebugBase = (VOID *)(UINTN)((UINTN)DebugBase - SizeOfHeaders);
            return (VOID *)((CHAR8 *)CodeViewEntryPointer + sizeof (EFI_IMAGE_DEBUG_CODEVIEW_MTOC_ENTRY));
          default:
            break;
        }
      }
    }
  }

  (void)SizeOfHeaders;
  return NULL;
}

/**
  Process "qXfer:object:read:annex:offset,length" request.

  Returns an XML document that contains loaded libraries. In our case it is
  information in the EFI Debug Image Table converted into an XML document.

  GDB will call with an arbitrary length (it can't know the real length and
  will reply with chunks of XML that are easy for us to deal with. Gdb will
  keep calling until we say we are done. XML doc looks like:

  <library-list>
    <library name="/a/a/c/d.dSYM"><segment address="0x10000000"/></library>
    <library name="/a/m/e/e.pdb"><segment address="0x20000000"/></library>
    <library name="/a/l/f/f.dll"><segment address="0x30000000"/></library>
  </library-list>

  Since we can not allocate memory in interrupt context this module has
  assumptions about how it will get called:
  1) Length will generally be max remote packet size (big enough)
  2) First Offset of an XML document read needs to be 0
  3) This code will return back small chunks of the XML document on every read.
     Each subsequent call will ask for the next available part of the document.

  Note: The only variable size element in the XML is:
  "  <library name=\"%s\"><segment address=\"%p\"/></library>\n" and it is
  based on the file path and name of the symbol file. If the symbol file name
  is bigger than the max gdb remote packet size we could update this code
  to respond back in chunks.

 @param Offset  offset into special data area
 @param Length  number of bytes to read starting at Offset

 **/
VOID
QxferLibrary (
  IN  UINTN  Offset,
  IN  UINTN  Length
  )
{
  VOID   *LoadAddress;
  CHAR8  *Pdb;
  UINTN  Size;

  if (Offset != gPacketqXferLibraryOffset) {
    SendError (GDB_EINVALIDARG);
    Print (L"\nqXferLibrary (%d, %d) != %d\n", Offset, Length, gPacketqXferLibraryOffset);

    // Force a retry from the beginning
    gPacketqXferLibraryOffset = 0;

    return;
  }

  if (Offset == 0) {
    gPacketqXferLibraryOffset += gXferObjectReadResponse ('m', "<library-list>\n");

    // The owner of the table may have had to ralloc it so grab a fresh copy every time
    // we assume qXferLibrary will get called over and over again until the entire XML table is
    // returned in a tight loop. Since we are in the debugger the table should not get updated
    gDebugTable              = gDebugImageTableHeader->EfiDebugImageInfoTable;
    gEfiDebugImageTableEntry = 0;
    return;
  }

  if (gDebugTable != NULL) {
    for ( ; gEfiDebugImageTableEntry < gDebugImageTableHeader->TableSize; gEfiDebugImageTableEntry++, gDebugTable++) {
      if (gDebugTable->NormalImage != NULL) {
        if ((gDebugTable->NormalImage->ImageInfoType == EFI_DEBUG_IMAGE_INFO_TYPE_NORMAL) &&
            (gDebugTable->NormalImage->LoadedImageProtocolInstance != NULL))
        {
          Pdb = PeCoffLoaderGetDebuggerInfo (
                  gDebugTable->NormalImage->LoadedImageProtocolInstance->ImageBase,
                  &LoadAddress,
                  NULL
                  );
          if (Pdb != NULL) {
            Size = AsciiSPrint (
                     gXferLibraryBuffer,
                     sizeof (gXferLibraryBuffer),
                     "  <library name=\"%a\"><segment address=\"0x%p\"/></library>\n",
                     Pdb,
                     LoadAddress
                     );
            if ((Size != 0) && (Size != (sizeof (gXferLibraryBuffer) - 1))) {
              gPacketqXferLibraryOffset += gXferObjectReadResponse ('m', gXferLibraryBuffer);

              // Update loop variables so we are in the right place when we get back
              gEfiDebugImageTableEntry++;
              gDebugTable++;
              return;
            } else {
              // We could handle <library> entires larger than sizeof (gXferLibraryBuffer) here if
              // needed by breaking up into N packets
              // "<library name=\"%s
              // the rest of the string (as many packets as required
              // \"><segment address=\"%d\"/></library> (fixed size)
              //
              // But right now we just skip any entry that is too big
            }
          }
        }
      }
    }
  }

  gXferObjectReadResponse ('l', "</library-list>\n");
  gPacketqXferLibraryOffset = 0;
  return;
}

/**
  Converts a 2-byte ASCII HEX string to the byte value.

  @param[in]  Chars  Two HEX chars to be converted into a byte value.

  @retval   The byte value of the hex characters.
**/
UINT8
HexToByte (
  CHAR8  Chars[2]
  )
{
  UINT8  Result;
  UINTN  Index;
  CHAR8  Char;

  Result = 0;
  for (Index = 0; Index < 2; Index++) {
    Char   = Chars[Index];
    Result = Result << 4;
    if (('0' <= Char) && (Char <= '9')) {
      Result |= (Char - '0');
    } else {
      Char = AsciiCharToUpper (Char);
      Result |= (10 + Char - 'A');
    }
  }

  return Result;
}

/**
  Converts a string to hex values string.

  @param[in]  Response      The null terminated response string in ASCII.
  @param[in]  Output        The buffer to print the hex string.
  @param[in]  BufferLength  The length of the Output buffer.

**/
VOID
ConvertResponseToHex (
  IN CHAR8   *Response,
  OUT CHAR8  *Output,
  IN UINTN   BufferLength
  )
{
  UINTN  Index;
  UINT8  Byte;

  //
  // Write each ASCII char into two HEX characters, making sure to leave room
  // for the null character at the end of the string.
  //

  Index = 0;
  while ((Response[Index] != 0) && (((Index * 2) + 1) < (BufferLength - 1))) {
    Byte                    = Response[Index];
    Output[Index * 2]       = mHexToStr[(Byte & 0xF0) >> 4];
    Output[(Index * 2) + 1] = mHexToStr[Byte & 0xF];
    Index++;
  }

  Output[Index * 2] = 0;
}

/**
  Read PCI registers

  @param[in]  Command       The null terminated response string in ASCII.
  @param[in]  Format        The width format of register vlaue for output. 
  @param[in]  Output        The buffer to print the PCI register string.
  @param[in]  MaxLength     The maximum length of the Output buffer.

**/

VOID
ReadPciRegisters (
  IN CHAR8   *Command,
  IN UINTN   Format,
  OUT CHAR8  *Output,
  IN UINTN   MaxLength
  )
{
  UINT32 Param[4];
  UINT32 Reg;
  UINT32 Addr;
  UINT32 Data;
  UINT32 Base;
  UINTN  Pos;
  UINTN  Index;
  UINT8  *Data8;
  UINT16 *Data16;
  CHAR8  AddressBuffer[MAX_ADDR_SIZE]; // the buffer that will hold the address in hex chars
  CHAR8  *AddrBufPtr;                  // pointer to the address buffer
  CHAR8  *InBufPtr;                    /// pointer to the input buffer

  Pos = 0;
  if (Command != NULL) {
    Param[0] = Param[1] = Param[2] = 0;
    Param[3] = 0x100;
    InBufPtr   = Command;
    for (Index = 0; Index < 4; Index ++) {
      AddrBufPtr = AddressBuffer;
      while (*InBufPtr != ',' && *InBufPtr != 0) {
        *AddrBufPtr++ = *InBufPtr++;
      }
      *AddrBufPtr = '\0';
      /* Error checking */
      if (AsciiStrLen (AddressBuffer) >= MAX_ADDR_SIZE) {
        Print ((CHAR16 *)L"Address is too long\n");
        SendError (GDB_EBADMEMADDRBUFSIZE);
        return;
      }
      Param[Index] = (UINT32)AsciiStrHexToUintn (AddressBuffer);
      if (*InBufPtr == 0) break;
      InBufPtr ++;
    }
    Data8  = (UINT8*)&Data;
    Data16 = (UINT16*)&Data;
    AsciiSPrint (
      Output + Pos,
      MaxLength - Pos,
      "PCI B:%02X D:%02X F:%02X\n\r",
      Param[0],
      Param[1],
      Param[2]
      );
    Pos += 20; 
    Addr = 0x80000000 | (Param[0] << 16) | (Param[1] << 11) | (Param[2] << 8);
    for (Base = 0; Base < Param[3] && Base < 0x100; Base += 16) {
      AsciiSPrint (
        Output + Pos,
        MaxLength - Pos,
        "%04X :",
        Base
        );
      Pos += 6;
      for (Reg = Base; Reg < Base + 16; Reg += 4) {
        IoWrite32 (0xcf8, Addr | Reg);
        Data = IoRead32 (0xcfc);
        switch (Format) {
          case 0: AsciiSPrint (Output + Pos, MaxLength - Pos, " %02X %02X %02X %02X", Data8[0], Data8[1], Data8[2], Data8[3]);
                  Pos += 12;
                  break;
          case 1: AsciiSPrint (Output + Pos, MaxLength - Pos, " %04X %04X", Data16[0], Data16[1]);
                  Pos += 10;
                  break;
          case 2: AsciiSPrint (Output + Pos, MaxLength - Pos, " %08X", Data);
                  Pos += 9;
                  break;
        }
      }
      AsciiSPrint (Output + Pos, MaxLength - Pos, "\n\r");
      Pos += 2;
    }
  } else {
    for (Param[0] = 0; Param[0] < 0xff; Param[0] ++) {
      for (Param[1] = 0; Param[1] < 0x20; Param[1] ++) {
        for (Param[2] = 0; Param[2] < 0x08; Param[2] ++) {
          Addr = 0x80000000 | (Param[0] << 16) | (Param[1] << 11) | (Param[2] << 8);
          IoWrite32 (0xcf8, Addr);
          Data = IoRead32 (0xcfc);
          if (Data != 0xffffffff) {
            AsciiSPrint (
              Output + Pos,
              MaxLength - Pos,
              "PCI B:%02X D:%02X F:%02X VID:%04X DID:%04X\n\r",
              Param[0],
              Param[1],
              Param[2],
              Data & 0xffff,
              Data >> 16
              );
            Pos += 38;
          }
        }
      }
    }
  }
}

/**
  Output debug string by "O" response packet

  @param[in]  String        The null terminated response string in ASCII.

**/
VOID
OutputDebugString (
  CHAR8 *String
  )
{
  gOutBuffer[0] = 'O';
  ConvertResponseToHex (String, gOutBuffer + 1, MAX_BUF_SIZE - 1);
  SendPacket (gOutBuffer);
}

/**
  Processes a custom qRcmd,#### command. These commands are specific to the UEFI
  debugger and may be expanded with functionality as needed.

  @param[in]  CommandHex  The HEX encoded string of the command.

**/
VOID
ProcessMonitorCmd (
  CHAR8  *CommandHex
  )
{
  UINTN  Index;
  UINTN  CommandLen;
  CHAR8  Command[128];

  // The command comes in hex encoded, convert it to a byte array.
  CommandLen = AsciiStrLen (CommandHex);
  if (((CommandLen % 2) != 0) || ((CommandLen / 2) >= sizeof (Command))) {
    SendError (GDB_EINVALIDARG);
    return;
  }

  CommandLen /= 2;
  for (Index = 0; Index < CommandLen; Index++) {
    Command[Index] = HexToByte (&CommandHex[Index * 2]);
  }

  Command[Index] = 0;

  //
  // Interpret the command. This is specific to the UEFI debugger and not
  // from the GDB specifications. Treat the first byte as the command.
  //

  switch (Command[0]) {
    case 'p': // PCI registers
      if (Command[1] == 0) {
        ReadPciRegisters (NULL, 0, gXferLibraryBuffer, MAX_BUF_SIZE);
      } else if (Command[1] == ' ') {
        ReadPciRegisters (Command + 2, 0, gXferLibraryBuffer, MAX_BUF_SIZE);
      } else if (Command[1] == 'w') {
        ReadPciRegisters (Command + 3, 1, gXferLibraryBuffer, MAX_BUF_SIZE);
      } else if (Command[1] == 'd') {
        ReadPciRegisters (Command + 3, 2, gXferLibraryBuffer, MAX_BUF_SIZE);
      }
      break;

    default:
      AsciiSPrint (gXferLibraryBuffer, 2000, "Unknown command '%a'\n\r", Command);
      break;
  }

  // RCmd commands return hex encoded responses, convert to HEX before sending.
  ConvertResponseToHex (gXferLibraryBuffer, gOutBuffer, MAX_BUF_SIZE);
  SendPacket (gOutBuffer);
}

/**
 Exception Handler for GDB. It will be called for all exceptions
 registered via the gExceptionType[] array.

 @param ExceptionType     Exception that is being processed
 @param SystemContext     Register content at time of the exception
 **/
VOID
EFIAPI
GdbExceptionHandler (
  IN  EFI_EXCEPTION_TYPE     ExceptionType,
  IN OUT EFI_SYSTEM_CONTEXT  SystemContext
  )
{
  UINT8  GdbExceptionType;
  CHAR8  *Ptr;

  if (ValidateException (ExceptionType, SystemContext) == FALSE) {
    return;
  }

  RemoveSingleStep (SystemContext);

  GdbExceptionType = ConvertEFItoGDBtype (ExceptionType);
  GdbSendTSignal (SystemContext, GdbExceptionType);

  for ( ; ; ) {
    ReceivePacket (gInBuffer, MAX_BUF_SIZE);

    switch (gInBuffer[0]) {
      case '?':
        GdbSendTSignal (SystemContext, GdbExceptionType);
        break;

      case 'c':
        ContinueAtAddress (SystemContext, gInBuffer);
        return;

      case 'g':
        ReadGeneralRegisters (SystemContext);
        break;

      case 'G':
        WriteGeneralRegisters (SystemContext, gInBuffer);
        break;

      case 'H':
        // Return "OK" packet since we don't have more than one thread.
        SendSuccess ();
        break;

      case 'm':
        ReadFromMemory (gInBuffer);
        break;

      case 'M':
        WriteToMemory (gInBuffer);
        break;

      case 'P':
        WriteNthRegister (SystemContext, gInBuffer);
        break;

      //
      // Still debugging this code. Not used in Darwin
      //
      case 'q':
        // General Query Packets
        if (AsciiStrnCmp (gInBuffer, "qSupported", 10) == 0) {
          // return what we currently support, we don't parse what gdb supports
          AsciiSPrint (gOutBuffer, MAX_BUF_SIZE, "qXfer:libraries:read+;qXfer:exec-file:read+;PacketSize=%d", MAX_BUF_SIZE);
          SendPacket (gOutBuffer);
        } else if (AsciiStrnCmp (gInBuffer, "qXfer:libraries:read::", 22) == 0) {
          // 'qXfer:libraries:read::offset,length
          // gInBuffer[22] is offset string, ++Ptr is length string'
          for (Ptr = &gInBuffer[22]; *Ptr != ','; Ptr++) {
          }
          // Not sure if multi-radix support is required. Currently only support decimal
          QxferLibrary (AsciiStrHexToUintn (&gInBuffer[22]), AsciiStrHexToUintn (++Ptr));
        } else if (AsciiStrnCmp (gInBuffer, "qXfer:exec-file:read::", 22) == 0) {
          if (gLoadedImageDebugPath != NULL) {
            AsciiSPrint (gOutBuffer, MAX_BUF_SIZE, "l%a", gLoadedImageDebugPath);
          } else {
            AsciiSPrint (gOutBuffer, MAX_BUF_SIZE, "l");
          }
          SendPacket (gOutBuffer);
        } else if (AsciiStrnCmp (gInBuffer, "qAttached", 9) == 0) {
          SendPacket ("1");
        } else if (AsciiStrnCmp (gInBuffer, "qRcmd,", 6) == 0) {
          ProcessMonitorCmd (gInBuffer + 6);
        } else if (AsciiStrnCmp (gInBuffer, "qOffsets", 10) == 0) {
          if (gLoadedImageCodeBase != NULL) {
            AsciiSPrint (gOutBuffer, MAX_BUF_SIZE, "TextSeg=%X", gLoadedImageCodeBase);
          }
          SendPacket (gOutBuffer);
        } else {
          // Send empty packet
          SendNotSupported ();
        }

        break;

      case 's':
        SingleStep (SystemContext, gInBuffer);
        return;

      case 'z':
        RemoveBreakPoint (SystemContext, gInBuffer);
        break;

      case 'Z':
        InsertBreakPoint (SystemContext, gInBuffer);
        break;

      default:
        // Send empty packet
        SendNotSupported ();
        break;
    }
  }
}

/**
 Periodic callback for GDB. This function is used to catch a ctrl-c or other
 break in type command from GDB.

 @param SystemContext     Register content at time of the call
 **/
VOID
EFIAPI
GdbPeriodicCallBack (
  IN OUT EFI_SYSTEM_CONTEXT  SystemContext
  )
{
  //
  // gCtrlCBreakFlag may have been set from a previous F response package
  // and we set the global as we need to process it at a point where we
  // can update the system context. If we are in the middle of processing
  // a F Packet it is not safe to read the GDB serial stream so we need
  // to skip it on this check
  //
  if (!gCtrlCBreakFlag && !gProcessingFPacket) {
    //
    // Ctrl-C was not pending so grab any pending characters and see if they
    // are a Ctrl-c (0x03). If so set the Ctrl-C global.
    //
    while (TRUE) {
      if (!GdbIsCharAvailable ()) {
        //
        // No characters are pending so exit the loop
        //
        break;
      }

      if (GdbGetChar () == 0x03) {
        gCtrlCBreakFlag = TRUE;
        //
        // We have a ctrl-c so exit the loop
        //
        break;
      }
    }
  }

  if (gCtrlCBreakFlag) {
    //
    // Update the context to force a single step trap when we exit the GDB
    // stub. This will transfer control to GdbExceptionHandler () and let
    // us break into the program. We don't want to break into the GDB stub.
    //
    AddSingleStep (SystemContext);
    gCtrlCBreakFlag = FALSE;
  }
}
