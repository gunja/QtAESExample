#include "wapi_enc.h"
#include <QDebug>

wAPI_AES_ECB_Encryptor::wAPI_AES_ECB_Encryptor()
{
        //BCRYPT_AES_ALGORITHM
        hAesAlg = nullptr;
        status = STATUS_UNSUCCESSFUL;
        cbPlainTextDone = 0;
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

wAPI_AES_ECB_Encryptor::~wAPI_AES_ECB_Encryptor()
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

QByteArray wAPI_AES_ECB_Encryptor::encrypt(const QByteArray &rawText, const QByteArray &key)
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
    DWORD cbPlainText = rawText.size();
    //align size to multiple of 16 bytes ( AES block length)
    if(cbPlainText % 16 ) { cbPlainText =(cbPlainText/16 ) + 1; cbPlainText *=16; }
    PBYTE pbPlainText = (PBYTE)HeapAlloc (GetProcessHeap (), 0, cbPlainText);
    if(NULL == pbPlainText)
    {
        qDebug()<<"**** memory allocation failed";
        if (hKey) { BCryptDestroyKey(hKey); }
        return retVal;
    }
    memset(pbPlainText, 0, cbPlainText);
    memcpy(pbPlainText, rawText.constData(), rawText.size() );

    //
    // Get the output buffer size.
    //
    DWORD cbCryptText;
    if(!NT_SUCCESS(status = BCryptEncrypt(
                                    hKey,
                                    pbPlainText,
                                    cbPlainText,
                                    NULL,
                                    NULL,
                                    0,
                                    NULL,
                                    0,
                                    &cbCryptText,
                                    0)))
    {
        qDebug()<<"**** Error "<<status<<" returned by BCryptDecrypt" ;
        if (hKey) { BCryptDestroyKey(hKey); }
        if(pbPlainText) { HeapFree(GetProcessHeap(), 0, pbPlainText); }
        return retVal;
    }

    PBYTE pbCryptText = (PBYTE)HeapAlloc (GetProcessHeap (), 0, cbCryptText);
    if(NULL == pbCryptText)
    {
        qDebug()<<"**** memory allocation failed";
        if (hKey) { BCryptDestroyKey(hKey); }
        if(pbPlainText) { HeapFree(GetProcessHeap(), 0, pbPlainText); }
        return retVal;
    }

    if(!NT_SUCCESS(status = BCryptEncrypt(
                                    hKey,
                                    pbPlainText,
                                    cbPlainText,
                                    NULL,
                                    NULL,
                                    0,
                                    pbCryptText,
                                    cbCryptText,
                                    &cbPlainTextDone,
                                    0)))
    {
        qDebug()<<"**** Error "<<hex<<(unsigned)status<<" returned by BCryptEncrypt" ;
        if (hKey) { BCryptDestroyKey(hKey); }
        if(pbPlainText) { HeapFree(GetProcessHeap(), 0, pbPlainText); }
        if(pbCryptText) { HeapFree(GetProcessHeap(), 0, pbCryptText); }
        return retVal;
    }
    retVal = QByteArray(reinterpret_cast<char*>(pbCryptText), cbCryptText);
    if (hKey) { BCryptDestroyKey(hKey); }
    if(pbCryptText) { HeapFree(GetProcessHeap(), 0, pbCryptText); }
    if(pbPlainText) { HeapFree(GetProcessHeap(), 0, pbPlainText); }
    return retVal;
}
