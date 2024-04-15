#include "antie.h"

BOOL IsDbgrPresent()
{
	PPEB  pPeb = (PPEB)(__readgsqword(0x60));

	if (pPeb->BeingDebugged == 1)
		return TRUE;


	return FALSE;
}

BOOL AllowMsLibOnly()
{
	PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY sigPolicy = { .MicrosoftSignedOnly = 1, .MitigationOptIn = 1 };

	if (!SetProcessMitigationPolicy(ProcessSignaturePolicy, &sigPolicy, sizeof(ProcessSignaturePolicy)))
		return FALSE;

	return TRUE;
}