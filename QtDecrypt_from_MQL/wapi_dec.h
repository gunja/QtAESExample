#ifndef WAPI_DEC_H
#define WAPI_DEC_H
#include <QByteArray>

#include <windows.h>
#include <stdio.h>
#include <bcrypt.h>
#define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)
#define STATUS_UNSUCCESSFUL         ((NTSTATUS)0xC0000001L)


class wAPI_AES_ECB_Decryptor
{
    BCRYPT_ALG_HANDLE hAesAlg;
    NTSTATUS    status;
    DWORD cbPlainTextDone, cbData, cbKeyObject, cbBlockLen, cbBlob;
    PBYTE pbKeyObject, pbBlob;
    bool valid;
public:
    wAPI_AES_ECB_Decryptor();
    ~wAPI_AES_ECB_Decryptor();
    QByteArray decrypt(const QByteArray &rawText, const QByteArray &key);
};

#endif // WAPI_DEC_H
