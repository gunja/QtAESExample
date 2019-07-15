#include "wapi_dec.h"
#include <QDebug>

wAPI_AES_ECB_Decryptor::wAPI_AES_ECB_Decryptor()
{
    //BCRYPT_AES_ALGORITHM
    hAesAlg = NULL;
    status = STATUS_UNSUCCESSFUL;
    cbPlainTextDone                 = 0;
    cbData = 0;
    cbKeyObject = 0;
    cbBlockLen = 0;
    cbBlob = 0;
    pbKeyObject = NULL;
    pbBlob = NULL;
    valid = false;
    if(!NT_SUCCESS(status = BCryptOpenAlgorithmProvider( &hAesAlg, BCRYPT_AES_ALGORITHM, NULL, 0)))
    {
        qDebug()<<"**** Error "<<status<<" returned by BCryptOpenAlgorithmProvider\n";
        return;
    }
    if(!NT_SUCCESS(status = BCryptGetProperty(
                                           hAesAlg,
                                           BCRYPT_OBJECT_LENGTH,
                                           (PBYTE)&cbKeyObject,
                                           sizeof(DWORD),
                                           &cbData,
                                           0)))
       {
           qDebug()<<"**** Error "<<status<<" returned by BCryptGetProperty\n";
           return;
       }
    // Allocate the key object on the heap.
    pbKeyObject = (PBYTE)HeapAlloc (GetProcessHeap (), 0, cbKeyObject);
    if(NULL == pbKeyObject)
    {
        qDebug()<<"**** memory allocation failed\n";
        return;
    }

   // Calculate the block length for the IV.
    if(!NT_SUCCESS(status = BCryptGetProperty(
                                        hAesAlg,
                                        BCRYPT_BLOCK_LENGTH,
                                        (PBYTE)&cbBlockLen,
                                        sizeof(DWORD),
                                        &cbData,
                                        0)))
    {
        qDebug()<<"**** Error "<<status<<" returned by BCryptGetProperty";
        return;
    }

    if(!NT_SUCCESS(status = BCryptSetProperty(
                                    hAesAlg,
                                    BCRYPT_CHAINING_MODE,
                                    (PBYTE)BCRYPT_CHAIN_MODE_ECB,
                                    sizeof(BCRYPT_CHAIN_MODE_ECB),
                                    0)))
    {
        qDebug()<<"**** Error "<<status<<" returned by BCryptSetProperty";
        return;
    }
    valid = true;
}


wAPI_AES_ECB_Decryptor::~wAPI_AES_ECB_Decryptor()
{
    if(hAesAlg)
    {
        BCryptCloseAlgorithmProvider(hAesAlg,0);
    }

    if(pbKeyObject)
    {
        HeapFree(GetProcessHeap(), 0, pbKeyObject);
    }
}

QByteArray wAPI_AES_ECB_Decryptor::decrypt(const QByteArray &rawText, const QByteArray &key)
{
    if( ! valid) return QByteArray();
    QByteArray exactKey (key);
    QByteArray retVal;
    if(exactKey.size() >= 32) exactKey = key.left(32);
    else if (exactKey.size() >= 24) exactKey = key.left(24);
    else if (exactKey.size() >= 16) exactKey = key.left(16);
    else {
        qDebug()<<"dont know how to handle key length "<<key.size();
    }
    BCRYPT_KEY_HANDLE hKey = nullptr;
    if(!NT_SUCCESS(status = BCryptGenerateSymmetricKey(
                                            hAesAlg,
                                            &hKey,
                                            pbKeyObject,
                                            cbKeyObject,
                                            (PBYTE)exactKey.constData() ,
                                            exactKey.size(),
                                            0)))
    {
        qDebug()<<"**** Error "<<status<<" returned by BCryptGenerateSymmetricKey";
        return retVal;
    }
    DWORD cbCipherText = rawText.size();
    PBYTE pbCipherText = (PBYTE)HeapAlloc (GetProcessHeap (), 0, cbCipherText);
    if(NULL == pbCipherText)
    {
        qDebug()<<"**** memory allocation failed";
        if (hKey) { BCryptDestroyKey(hKey); }
        return retVal;
    }
    memcpy(pbCipherText, rawText.constData(), cbCipherText );

    //
    // Get the output buffer size.
    //
    DWORD cbPlainText;
    if(!NT_SUCCESS(status = BCryptDecrypt(
                                    hKey,
                                    pbCipherText,
                                    cbCipherText,
                                    NULL,
                                    NULL,
                                    0,
                                    NULL,
                                    0,
                                    &cbPlainText,
                                    BCRYPT_BLOCK_PADDING)))
    {
        qDebug()<<"**** Error "<<status<<" returned by BCryptDecrypt" ;
        if (hKey) { BCryptDestroyKey(hKey); }
        if(pbCipherText) { HeapFree(GetProcessHeap(), 0, pbCipherText); }
        return retVal;
    }

    PBYTE pbPlainText = (PBYTE)HeapAlloc (GetProcessHeap (), 0, cbPlainText);
    if(NULL == pbPlainText)
    {
        qDebug()<<"**** memory allocation failed";
        if (hKey) { BCryptDestroyKey(hKey); }
        if(pbCipherText) { HeapFree(GetProcessHeap(), 0, pbCipherText); }
        return retVal;
    }

    if(!NT_SUCCESS(status = BCryptDecrypt(
                                    hKey,
                                    pbCipherText,
                                    cbCipherText,
                                    NULL,
                                    NULL,
                                    0,
                                    pbPlainText,
                                    cbPlainText,
                                    &cbPlainTextDone,
                                    //BCRYPT_BLOCK_PADDING)))
                       //BCRYPT_PAD_NONE )))
                       0 )))
    {
        qDebug()<<"**** Error "<<hex<<(unsigned)status<<" returned by BCryptDecrypt" ;
        if (hKey) { BCryptDestroyKey(hKey); }
        if(pbCipherText) { HeapFree(GetProcessHeap(), 0, pbCipherText); }
        if(pbPlainText) { HeapFree(GetProcessHeap(), 0, pbPlainText); }
        return retVal;
    }
    retVal = QByteArray(reinterpret_cast<char*>(pbPlainText), rawText.size());
    if (hKey) { BCryptDestroyKey(hKey); }
    if(pbCipherText) { HeapFree(GetProcessHeap(), 0, pbCipherText); }
    if(pbPlainText) { HeapFree(GetProcessHeap(), 0, pbPlainText); }
    return retVal;
}
