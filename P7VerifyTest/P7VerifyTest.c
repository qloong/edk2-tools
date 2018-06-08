/** @file
  UEFI PKCS7 Verification Protocol test application.

Copyright (c) 2015, Intel Corporation. All rights reserved.<BR>
This program and the accompanying materials
are licensed and made available under the terms and conditions of the BSD License
which accompanies this distribution.  The full text of the license may be found at
http://opensource.org/licenses/bsd-license.php

THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/UefiApplicationEntryPoint.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Protocol/Pkcs7Verify.h>

#include "P7VerifyBufferTestData.h"
#include "P7VerifySignatureTestData.h"

EFI_SIGNATURE_LIST *AllowedDb[3]   = { NULL, NULL, NULL };
EFI_SIGNATURE_LIST *RevokedDb[3]   = { NULL, NULL, NULL };
EFI_SIGNATURE_LIST *TimestampDb[3] = { NULL, NULL, NULL };

EFI_PKCS7_VERIFY_PROTOCOL *P7Protocol = NULL;

EFI_STATUS
ValidatePkcs7VerifyBuffer (
  VOID
  )
{
  EFI_STATUS          Status;
  EFI_SIGNATURE_LIST  *DbEntry1;
  EFI_SIGNATURE_LIST  *DbEntry2;
  EFI_SIGNATURE_LIST  *DbEntry3;
  EFI_SIGNATURE_LIST  *DbEntry4;
  EFI_SIGNATURE_LIST  *DbEntry5;
  EFI_TIME            *RevokedTime;

  ASSERT (P7Protocol != NULL);

  Status    = EFI_SUCCESS;
  DbEntry1  = NULL;
  DbEntry2  = NULL;
  DbEntry3  = NULL;
  DbEntry4  = NULL;
  DbEntry5  = NULL;
  RevokedTime = 0;

  //
  // Initialize Signature List Entry for testing.
  //
  // Signature List of TestRoot Certificate
  //
  DbEntry1 = AllocatePool (sizeof (EFI_SIGNATURE_LIST) + 16 + sizeof (TestRootCert));
  DbEntry1->SignatureType       = gEfiCertX509Guid;
  DbEntry1->SignatureListSize   = sizeof (EFI_SIGNATURE_LIST) + 16 + sizeof (TestRootCert);
  DbEntry1->SignatureHeaderSize = 0;
  DbEntry1->SignatureSize       = 16 + sizeof (TestRootCert);
  CopyMem ((UINT8 *)DbEntry1 + sizeof (EFI_SIGNATURE_LIST) + 16, TestRootCert, sizeof (TestRootCert));

  //
  // Signature List of TestSub Certificate
  //
  DbEntry2 = AllocatePool (sizeof (EFI_SIGNATURE_LIST) + 16 + sizeof (TestSubCert));
  DbEntry2->SignatureType       = gEfiCertX509Guid;
  DbEntry2->SignatureListSize   = sizeof (EFI_SIGNATURE_LIST) + 16 + sizeof (TestSubCert);
  DbEntry2->SignatureHeaderSize = 0;
  DbEntry2->SignatureSize       = 16 + sizeof (TestSubCert);
  CopyMem ((UINT8 *)DbEntry2 + sizeof (EFI_SIGNATURE_LIST) + 16, TestSubCert, sizeof (TestSubCert));

  //
  // Signature List of TSRoot Certificate
  //
  DbEntry3 = AllocatePool (sizeof (EFI_SIGNATURE_LIST) + 16 + sizeof (TSRootCert));
  DbEntry3->SignatureType       = gEfiCertX509Guid;
  DbEntry3->SignatureListSize   = sizeof (EFI_SIGNATURE_LIST) + 16 + sizeof (TSRootCert);
  DbEntry3->SignatureHeaderSize = 0;
  DbEntry3->SignatureSize       = 16 + sizeof (TSRootCert);
  CopyMem ((UINT8 *)DbEntry3 + sizeof (EFI_SIGNATURE_LIST) + 16, TSRootCert, sizeof (TSRootCert));

  //
  // Signature List of Binary Data Hash for Revocation Checking
  //
  DbEntry4 = AllocatePool (sizeof (EFI_SIGNATURE_LIST) + 16 + 32);
  DbEntry4->SignatureType       = gEfiCertSha256Guid;
  DbEntry4->SignatureListSize   = sizeof (EFI_SIGNATURE_LIST) + 16 + 32;
  DbEntry4->SignatureHeaderSize = 0;
  DbEntry4->SignatureSize       = 16 + 32;
  CopyMem ((UINT8 *)DbEntry4 + sizeof (EFI_SIGNATURE_LIST) + 16, TestBinHash, 32);

  //
  // Signature List of Certificate Hash for Timestamp Signature Checking
  //
  DbEntry5 = AllocatePool (sizeof (EFI_SIGNATURE_LIST) + 16 + 48);
  DbEntry5->SignatureType       = gEfiCertX509Sha256Guid;
  DbEntry5->SignatureListSize   = sizeof (EFI_SIGNATURE_LIST) + 16 + 48;
  DbEntry5->SignatureHeaderSize = 0;
  DbEntry5->SignatureSize       = 16 + 48;
  CopyMem ((UINT8 *)DbEntry5 + sizeof (EFI_SIGNATURE_LIST) + 16, TestSubHash, 32);
  RevokedTime = (EFI_TIME *) ((UINT8 *)DbEntry5 + sizeof (EFI_SIGNATURE_LIST) + 16 + 32);
  RevokedTime->Year  = 2015;
  RevokedTime->Month = 06;
  RevokedTime->Day   = 16;

  //-------------------------------------------------
  // P7Protocol->VerifyBuffer() with Embedded P7Data
  //-------------------------------------------------
  Print (L" --> P7Protocol->VerifyBufer() Testings on Embedded P7Data...\n");

  //
  // ALL NULL DB
  //
  Print (L"   |--> Validating P7Data with NULL DB :      ");
  Status = P7Protocol->VerifyBuffer (
                         P7Protocol,
                         P7Embedded,
                         sizeof (P7Embedded),
                         NULL,
                         0,
                         AllowedDb,
                         RevokedDb,
                         TimestampDb,
                         NULL,
                         0
                         );
  if (EFI_ERROR (Status)) {
    Print (L"[Fail - (%r)]\n", Status);
  } else {
    Print (L"[Pass]\n");
  }

  //
  // AllowedDb Testing
  //
  Print (L"   |--> Validating P7Data with AllowedDB :    ");

  AllowedDb[0] = DbEntry1;
  Status = P7Protocol->VerifyBuffer (
                         P7Protocol,
                         P7Embedded,
                         sizeof (P7Embedded),
                         NULL,
                         0,
                         AllowedDb,
                         RevokedDb,
                         TimestampDb,
                         NULL,
                         0
                         );
  if (EFI_ERROR (Status)) {
    Print (L"[Fail - (%r)]\n", Status);
  } else {
    Print (L"[Pass]\n");
  }

  //
  // Add RevokedDb to testing Content Hash Revocation
  //
  Print (L"   |--> Validating P7Data with RevokedDB :    ");

  RevokedDb[0] = DbEntry4;
  Status = P7Protocol->VerifyBuffer (
                         P7Protocol,
                         P7Embedded,
                         sizeof (P7Embedded),
                         NULL,
                         0,
                         AllowedDb,
                         RevokedDb,
                         TimestampDb,
                         NULL,
                         0
                         );
  if (EFI_ERROR (Status)) {
    Print (L"[Fail - (%r)]\n", Status);
  } else {
    Print (L"[Pass]\n");
  }


  //
  // Add RevokedDb Testing
  //
  Print (L"   |--> Validating P7Data with RevokedDB :    ");

  RevokedDb[0] = DbEntry2;
  Status = P7Protocol->VerifyBuffer (
                         P7Protocol,
                         P7Embedded,
                         sizeof (P7Embedded),
                         NULL,
                         0,
                         AllowedDb,
                         RevokedDb,
                         TimestampDb,
                         NULL,
                         0
                         );
  if (EFI_ERROR (Status)) {
    Print (L"[Fail - (%r)]\n", Status);
  } else {
    Print (L"[Pass]\n");
  }

  //
  // Add TimeStampDb Testing
  //
  Print (L"   |--> Validating P7Data with TimestampDB :  ");

  RevokedDb[0]   = DbEntry5;
  TimestampDb[0] = DbEntry3;
  Status = P7Protocol->VerifyBuffer (
                         P7Protocol,
                         P7Embedded,
                         sizeof (P7Embedded),
                         NULL,
                         0,
                         AllowedDb,
                         RevokedDb,
                         TimestampDb,
                         NULL,
                         0
                         );
  if (EFI_ERROR (Status)) {
    Print (L"[Fail - (%r)]\n", Status);
  } else {
    Print (L"[Pass]\n");
  }

  Print (L" --> VerifyBufer() Testings on Detached P7Data...\n");

  //-------------------------------------------------
  // P7Protocol->VerifyBuffer() with Detached P7Data
  //-------------------------------------------------

  //
  // ALL NULL DB
  //
  AllowedDb[0]   = NULL;
  RevokedDb[0]   = NULL;
  TimestampDb[0] = NULL;
  Print (L"   |--> Validating P7Data with NULL DB :      ");
  Status = P7Protocol->VerifyBuffer (
                         P7Protocol,
                         P7Detached,
                         sizeof (P7Detached),
                         TestBin,
                         sizeof (TestBin),
                         AllowedDb,
                         RevokedDb,
                         TimestampDb,
                         NULL,
                         0
                         );
  if (EFI_ERROR (Status)) {
    Print (L"[Fail - (%r)]\n", Status);
  } else {
    Print (L"[Pass]\n");
  }

  //
  // AllowedDb Testing
  //
  Print (L"   |--> Validating P7Data with AllowedDB :    ");

  AllowedDb[0] = DbEntry1;
  Status = P7Protocol->VerifyBuffer (
                         P7Protocol,
                         P7Detached,
                         sizeof (P7Detached),
                         TestBin,
                         sizeof (TestBin),
                         AllowedDb,
                         RevokedDb,
                         TimestampDb,
                         NULL,
                         0
                         );
  if (EFI_ERROR (Status)) {
    Print (L"[Fail - (%r)]\n", Status);
  } else {
    Print (L"[Pass]\n");
  }

  //
  // Add RevokedDb to testing Content Hash Revocation
  //
  Print (L"   |--> Validating P7Data with RevokedDB :    ");

  RevokedDb[0] = DbEntry4;
  Status = P7Protocol->VerifyBuffer (
                         P7Protocol,
                         P7Detached,
                         sizeof (P7Detached),
                         TestBin,
                         sizeof (TestBin),
                         AllowedDb,
                         RevokedDb,
                         TimestampDb,
                         NULL,
                         0
                         );
  if (EFI_ERROR (Status)) {
    Print (L"[Fail - (%r)]\n", Status);
  } else {
    Print (L"[Pass]\n");
  }


  //
  // Add RevokedDb Testing
  //
  Print (L"   |--> Validating P7Data with RevokedDB :    ");

  RevokedDb[0] = DbEntry2;
  Status = P7Protocol->VerifyBuffer (
                         P7Protocol,
                         P7Detached,
                         sizeof (P7Detached),
                         TestBin,
                         sizeof (TestBin),
                         AllowedDb,
                         RevokedDb,
                         TimestampDb,
                         NULL,
                         0
                         );
  if (EFI_ERROR (Status)) {
    Print (L"[Fail - (%r)]\n", Status);
  } else {
    Print (L"[Pass]\n");
  }

  //
  // Add TimeStampDb Testing
  //
  Print (L"   |--> Validating P7Data with TimestampDB :  ");

  TimestampDb[0] = DbEntry3;
  Status = P7Protocol->VerifyBuffer (
                         P7Protocol,
                         P7Detached,
                         sizeof (P7Detached),
                         TestBin,
                         sizeof (TestBin),
                         AllowedDb,
                         RevokedDb,
                         TimestampDb,
                         NULL,
                         0
                         );
  if (EFI_ERROR (Status)) {
    Print (L"[Fail - (%r)]\n", Status);
  } else {
    Print (L"[Pass]\n");
  }

  if (DbEntry1 != NULL) {
    FreePool (DbEntry1);
  }
  if (DbEntry2 != NULL) {
    FreePool (DbEntry2);
  }
  if (DbEntry3 != NULL) {
    FreePool (DbEntry3);
  }
  if (DbEntry4 != NULL) {
    FreePool (DbEntry4);
  }
  if (DbEntry5 != NULL) {
    FreePool (DbEntry5);
  }

  return Status;
}

EFI_STATUS
ValidatePkcs7VerifySignature (
  VOID
  )
{
  EFI_STATUS          Status;
  EFI_SIGNATURE_LIST  *DbEntry1;
  EFI_SIGNATURE_LIST  *DbEntry2;
  EFI_SIGNATURE_LIST  *DbEntry3;
  EFI_SIGNATURE_LIST  *DbEntry4;
  EFI_SIGNATURE_LIST  *DbEntry5;
  EFI_TIME            *RevokedTime;

  ASSERT (P7Protocol != NULL);

  Status    = EFI_SUCCESS;

  DbEntry1  = NULL;
  DbEntry2  = NULL;
  DbEntry3  = NULL;
  DbEntry4  = NULL;
  DbEntry5  = NULL;
  RevokedTime = 0;

  //
  // Initialize Signature List Entry for testing.
  //
  // Signature List of TestRoot Certificate
  //
  DbEntry1 = AllocatePool (sizeof (EFI_SIGNATURE_LIST) + 16 + sizeof (TestRootCert2));
  DbEntry1->SignatureType       = gEfiCertX509Guid;
  DbEntry1->SignatureListSize   = sizeof (EFI_SIGNATURE_LIST) + 16 + sizeof (TestRootCert2);
  DbEntry1->SignatureHeaderSize = 0;
  DbEntry1->SignatureSize       = 16 + sizeof (TestRootCert2);
  CopyMem ((UINT8 *)DbEntry1 + sizeof (EFI_SIGNATURE_LIST) + 16, TestRootCert2, sizeof (TestRootCert2));

  //
  // Signature List of TestSub Certificate
  //
  DbEntry2 = AllocatePool (sizeof (EFI_SIGNATURE_LIST) + 16 + sizeof (TestSubCert2));
  DbEntry2->SignatureType       = gEfiCertX509Guid;
  DbEntry2->SignatureListSize   = sizeof (EFI_SIGNATURE_LIST) + 16 + sizeof (TestSubCert2);
  DbEntry2->SignatureHeaderSize = 0;
  DbEntry2->SignatureSize       = 16 + sizeof (TestSubCert2);
  CopyMem ((UINT8 *)DbEntry2 + sizeof (EFI_SIGNATURE_LIST) + 16, TestSubCert2, sizeof (TestSubCert2));

  //
  // Signature List of TSRoot Certificate
  //
  DbEntry3 = AllocatePool (sizeof (EFI_SIGNATURE_LIST) + 16 + sizeof (TSRootCert2));
  DbEntry3->SignatureType       = gEfiCertX509Guid;
  DbEntry3->SignatureListSize   = sizeof (EFI_SIGNATURE_LIST) + 16 + sizeof (TSRootCert2);
  DbEntry3->SignatureHeaderSize = 0;
  DbEntry3->SignatureSize       = 16 + sizeof (TSRootCert2);
  CopyMem ((UINT8 *)DbEntry3 + sizeof (EFI_SIGNATURE_LIST) + 16, TSRootCert2, sizeof (TSRootCert2));

  //
  // Signature List of Binary Data Hash for Revocation Checking
  //
  DbEntry4 = AllocatePool (sizeof (EFI_SIGNATURE_LIST) + 16 + 32);
  DbEntry4->SignatureType       = gEfiCertSha256Guid;
  DbEntry4->SignatureListSize   = sizeof (EFI_SIGNATURE_LIST) + 16 + 32;
  DbEntry4->SignatureHeaderSize = 0;
  DbEntry4->SignatureSize       = 16 + 32;
  CopyMem ((UINT8 *)DbEntry4 + sizeof (EFI_SIGNATURE_LIST) + 16, TestInHash, 32);

  //
  // Signature List of Certificate Hash for Timestamp Signature Checking
  //
  DbEntry5 = AllocatePool (sizeof (EFI_SIGNATURE_LIST) + 16 + 48);
  DbEntry5->SignatureType       = gEfiCertX509Sha256Guid;
  DbEntry5->SignatureListSize   = sizeof (EFI_SIGNATURE_LIST) + 16 + 48;
  DbEntry5->SignatureHeaderSize = 0;
  DbEntry5->SignatureSize       = 16 + 48;
  CopyMem ((UINT8 *)DbEntry5 + sizeof (EFI_SIGNATURE_LIST) + 16, TestSubCertHash2, 32);
  RevokedTime = (EFI_TIME *) ((UINT8 *)DbEntry5 + sizeof (EFI_SIGNATURE_LIST) + 16 + 32);
  RevokedTime->Year  = 2018;
  RevokedTime->Month = 01;
  RevokedTime->Day   = 26;

  //---------------------------------------------------------------------
  // P7Protocol->VerifyBuffer() with DER-encoded detached PKCS7 Signature
  //
  //---------------------------------------------------------------------
  Print (L" --> P7Protocol->VerifySignature() Testings on Embedded P7Data...\n");

  //
  // ALL NULL DB
  //
  Print (L"   |--> Validating P7Signature with NULL DB :      ");
  Status = P7Protocol->VerifySignature (
                         P7Protocol,
                         P7TestSignature,
                         sizeof (P7TestSignature),
                         TestInHash,
                         sizeof (TestInHash),
                         AllowedDb,
                         RevokedDb,
                         TimestampDb
                         );
  if (Status == EFI_SECURITY_VIOLATION) {
    Print (L"[Pass - Blocked]\n");
  } else {
    Print (L"[Failed]\n");
  }

  //
  // AllowedDb Testing
  //
  Print (L"   |--> Validating P7Signature with AllowedDB :    ");

  AllowedDb[0] = DbEntry1;
  Status = P7Protocol->VerifySignature (
                         P7Protocol,
                         P7TestSignature,
                         sizeof (P7TestSignature),
                         TestInHash,
                         sizeof (TestInHash),
                         AllowedDb,
                         RevokedDb,
                         TimestampDb
                         );
  if (EFI_ERROR (Status)) {
    Print (L"[Fail - (%r)]\n", Status);
  } else {
    Print (L"[Pass - Verified]\n");
  }

  //
  // Add RevokedDb to testing Content Hash Revocation
  //
  Print (L"   |--> Validating P7Signature with RevokedDB :    ");

  RevokedDb[0] = DbEntry4;
  Status = P7Protocol->VerifySignature (
                         P7Protocol,
                         P7TestSignature,
                         sizeof (P7TestSignature),
                         TestInHash,
                         sizeof (TestInHash),
                         AllowedDb,
                         RevokedDb,
                         TimestampDb
                         );
  if (Status == EFI_SECURITY_VIOLATION) {
    Print (L"[Pass - Blocked]\n");
  } else {
    Print (L"[Failed]\n");
  }

  //
  // Add RevokedDb Testing
  //
  Print (L"   |--> Validating P7Signature with RevokedDB :    ");

  RevokedDb[0] = DbEntry2;
  Status = P7Protocol->VerifySignature (
                         P7Protocol,
                         P7TestSignature,
                         sizeof (P7TestSignature),
                         TestInHash,
                         sizeof (TestInHash),
                         AllowedDb,
                         RevokedDb,
                         TimestampDb
                         );
  if (Status == EFI_SECURITY_VIOLATION) {
    Print (L"[Pass - Blocked]\n");
  } else {
    Print (L"[Failed]\n");
  }

  //
  // Add TimeStampDb Testing
  //
  Print (L"   |--> Validating P7Signature with TimestampDB :  ");

  RevokedDb[0]   = DbEntry5;
  TimestampDb[0] = DbEntry3;
  AllowedDb[0]   = DbEntry1;
  Status = P7Protocol->VerifySignature (
                         P7Protocol,
                         P7TestSignature,
                         sizeof (P7TestSignature),
                         TestInHash,
                         sizeof (TestInHash),
                         AllowedDb,
                         RevokedDb,
                         TimestampDb
                         );
  if (EFI_ERROR (Status)) {
    Print (L"[Fail - (%r)]\n", Status);
  } else {
    Print (L"[Pass - Verified]\n");
  }

  if (DbEntry1 != NULL) {
    FreePool (DbEntry1);
  }
  if (DbEntry2 != NULL) {
    FreePool (DbEntry2);
  }
  if (DbEntry3 != NULL) {
    FreePool (DbEntry3);
  }
  if (DbEntry4 != NULL) {
    FreePool (DbEntry4);
  }
  if (DbEntry5 != NULL) {
    FreePool (DbEntry5);
  }

  return Status;
}

/**
  The user Entry Point for Application. The user code starts with this function
  as the real entry point for the application.

  @param[in] ImageHandle    The firmware allocated handle for the EFI image.
  @param[in] SystemTable    A pointer to the EFI System Table.

  @retval EFI_SUCCESS       The entry point is executed successfully.
  @retval other             Some error occurs when executing this entry point.

**/
EFI_STATUS
EFIAPI
UefiMain (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS                Status;

  Status    = EFI_SUCCESS;

  Print (L"UEFI PKCS7 Verification Protocol Testing :\n");
  Print (L"-------------------------------------------\n");

  //---------------------------------------------
  // Basic UEFI PKCS7 Verification Protocol Test
  //---------------------------------------------
  Print (L" --> Locate UEFI PKCS7 Verification Protocol : ");
  Status = gBS->LocateProtocol (&gEfiPkcs7VerifyProtocolGuid, NULL, (VOID **)&P7Protocol);
  if (EFI_ERROR (Status)) {
    Print (L"[Fail - Status = %r]\n", Status);
    return Status;
  } else {
    Print (L"[Pass]\n");
  }

  Status = ValidatePkcs7VerifySignature ();
//  Status = ValidatePkcs7VerifyBuffer ();

  return Status;
}
