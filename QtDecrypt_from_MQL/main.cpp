#include "qaesencryption.h"
#include <QFile>
#include <QByteArray>
#include <QDebug>
#include <stdlib.h>
#ifdef _WIN32
    #include <windows.h>
    #include <stdio.h>
    #include <bcrypt.h>
    #define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)
    #define STATUS_UNSUCCESSFUL         ((NTSTATUS)0xC0000001L)
#endif

#include <QElapsedTimer>

class wAPI_AES_ECB_Decryptor
{
    BCRYPT_ALG_HANDLE hAesAlg;
    BCRYPT_KEY_HANDLE hKey;
    NTSTATUS    status;
    DWORD cbCipherText, cbPlainText, cbPlainTextDone, cbData, cbKeyObject, cbBlockLen, cbBlob;
    PBYTE pbCipherText, pbPlainText, pbKeyObject, pbBlob;
    bool valid;
    public:
        wAPI_AES_ECB_Decryptor()
        {
            //BCRYPT_AES_ALGORITHM
            hAesAlg = NULL;
            hKey = NULL;
            status = STATUS_UNSUCCESSFUL;
            cbCipherText = 0;
            cbPlainText                 = 0;
            cbPlainTextDone                 = 0;
            cbData = 0;
            cbKeyObject = 0;
            cbBlockLen = 0;
            cbBlob = 0;
            pbCipherText = NULL;
            pbPlainText = NULL;
            pbKeyObject = NULL;
            pbBlob = NULL;
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
        }
        ~wAPI_AES_ECB_Decryptor()
        {
            if(hAesAlg)
            {
                BCryptCloseAlgorithmProvider(hAesAlg,0);
            }

            if (hKey)
            {
                BCryptDestroyKey(hKey);
            }

            if(pbCipherText)
            {
                HeapFree(GetProcessHeap(), 0, pbCipherText);
            }

            if(pbPlainText)
            {
                HeapFree(GetProcessHeap(), 0, pbPlainText);
            }

            if(pbKeyObject)
            {
                HeapFree(GetProcessHeap(), 0, pbKeyObject);
            }
        }
        QByteArray decrypt(const QByteArray &rawText, const QByteArray &key)
        {
            QByteArray exactKey (key);
            bool rvOK = false;
            QByteArray retVal;
            if(exactKey.size() >= 32) exactKey = key.left(32);
            else if (exactKey.size() >= 24) exactKey = key.left(24);
            else if (exactKey.size() >= 16) exactKey = key.left(16);
            else {
                qDebug()<<"dont know how to handle key length "<<key.size();
            }
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
            cbCipherText = rawText.size();
            pbCipherText = (PBYTE)HeapAlloc (GetProcessHeap (), 0, cbCipherText);
            if(NULL == pbCipherText)
            {
                qDebug()<<"**** memory allocation failed";
                return retVal;
            }

            memcpy(pbCipherText, rawText.constData(), cbCipherText );

            //
            // Get the output buffer size.
            //
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
                return retVal;
            }

            pbPlainText = (PBYTE)HeapAlloc (GetProcessHeap (), 0, cbPlainText);
            if(NULL == pbPlainText)
            {
                qDebug()<<"**** memory allocation failed";
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
                return retVal;
            }

            rvOK = true;
            retVal = QByteArray(reinterpret_cast<char*>(pbPlainText), rawText.size());
            return retVal;
        }
};

// key length is determinedd automatically.
// ECB mode
// Initialization vector is not used
QByteArray WinDecrypt(const QByteArray &rawText, const QByteArray &key)
{
#ifdef _WIN32
    QByteArray exactKey (key);
    bool rvOK = false;
    QByteArray retVal;
    if(exactKey.size() >= 32) exactKey = key.left(32);
    else if (exactKey.size() >= 24) exactKey = key.left(24);
    else if (exactKey.size() >= 16) exactKey = key.left(16);
    else {
        qDebug()<<"dont know how to handle key length "<<key.size();
    }

    //BCRYPT_AES_ALGORITHM
    BCRYPT_ALG_HANDLE       hAesAlg                     = NULL;
    BCRYPT_KEY_HANDLE       hKey                        = NULL;
    NTSTATUS                status                      = STATUS_UNSUCCESSFUL;
    DWORD                   cbCipherText                = 0,
                            cbPlainText                 = 0,
                            cbPlainTextDone                 = 0,
                            cbData                      = 0,
                            cbKeyObject                 = 0,
                            cbBlockLen                  = 0,
                            cbBlob                      = 0;
    PBYTE                   pbCipherText                = NULL,
                            pbPlainText                 = NULL,
                            pbKeyObject                 = NULL,
                            pbBlob                      = NULL;

    if(!NT_SUCCESS(status = BCryptOpenAlgorithmProvider(
                                                    &hAesAlg,
                                                    BCRYPT_AES_ALGORITHM,
                                                    NULL,
                                                    0)))
    {
        qDebug()<<"**** Error "<<status<<" returned by BCryptOpenAlgorithmProvider\n";
        goto Cleanup;
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
           goto Cleanup;
       }
    // Allocate the key object on the heap.
    pbKeyObject = (PBYTE)HeapAlloc (GetProcessHeap (), 0, cbKeyObject);
    if(NULL == pbKeyObject)
    {
        qDebug()<<"**** memory allocation failed\n";
        goto Cleanup;
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
        goto Cleanup;
    }

    if(!NT_SUCCESS(status = BCryptSetProperty(
                                    hAesAlg,
                                    BCRYPT_CHAINING_MODE,
                                    (PBYTE)BCRYPT_CHAIN_MODE_ECB,
                                    sizeof(BCRYPT_CHAIN_MODE_ECB),
                                    0)))
    {
        qDebug()<<"**** Error "<<status<<" returned by BCryptSetProperty";
        goto Cleanup;
    }
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
        goto Cleanup;
    }
    // Save another copy of the key for later.
        if(!NT_SUCCESS(status = BCryptExportKey(
                                            hKey,
                                            NULL,
                                            BCRYPT_OPAQUE_KEY_BLOB,
                                            NULL,
                                            0,
                                            &cbBlob,
                                            0)))
        {
            qDebug()<<"**** Error "<<status<<" returned by BCryptExportKey" ;
            goto Cleanup;
        }


        // Allocate the buffer to hold the BLOB.
        pbBlob = (PBYTE)HeapAlloc (GetProcessHeap (), 0, cbBlob);
        if(NULL == pbBlob)
        {
            qDebug()<<"**** memory allocation failed";
            goto Cleanup;
        }

        if(!NT_SUCCESS(status = BCryptExportKey(
                                            hKey,
                                            NULL,
                                            BCRYPT_OPAQUE_KEY_BLOB,
                                            pbBlob,
                                            cbBlob,
                                            &cbBlob,
                                            0)))
        {
            qDebug()<<"**** Error "<<status<<" returned by BCryptExportKey" ;
            goto Cleanup;
        }

        cbCipherText = rawText.size();
        pbCipherText = (PBYTE)HeapAlloc (GetProcessHeap (), 0, cbCipherText);
        if(NULL == pbCipherText)
        {
            qDebug()<<"**** memory allocation failed";
            goto Cleanup;
        }

        memcpy(pbCipherText, rawText.constData(), cbCipherText );

        //
        // Get the output buffer size.
        //
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
            goto Cleanup;
        }

        pbPlainText = (PBYTE)HeapAlloc (GetProcessHeap (), 0, cbPlainText);
        if(NULL == pbPlainText)
        {
            qDebug()<<"**** memory allocation failed";
            goto Cleanup;
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
            goto Cleanup;
        }

        rvOK = true;
        retVal = QByteArray(reinterpret_cast<char*>(pbPlainText), rawText.size());

    Cleanup:

        if(hAesAlg)
        {
            BCryptCloseAlgorithmProvider(hAesAlg,0);
        }

        if (hKey)
        {
            BCryptDestroyKey(hKey);
        }

        if(pbCipherText)
        {
            HeapFree(GetProcessHeap(), 0, pbCipherText);
        }

        if(pbPlainText)
        {
            HeapFree(GetProcessHeap(), 0, pbPlainText);
        }

        if(pbKeyObject)
        {
            HeapFree(GetProcessHeap(), 0, pbKeyObject);
        }
        return retVal;
#endif
}

int main(int argc, char *argv[])
{
    char key[] ="Some Cool Password1234567890-123"; // only 32 bytes are used
    QByteArray qbKey ( key);
    if( argc < 2) {
        qDebug()<<"not enough args";
        return 1;
    }
    QFile fin(argv[1]);
    if( ! fin.open(QIODevice::ReadOnly )) {
        qDebug()<<"failed to open "<<argv[1]<<" ce la vie";
        return 0;
    }
    QByteArray line = fin.readAll();
    QElapsedTimer timer, timer2;
    timer.start();
    QByteArray qbr = QAESEncryption::Decrypt(QAESEncryption::AES_256, QAESEncryption::ECB,
                           line, qbKey);
    qDebug() << "The slow operation took" << timer.nsecsElapsed() << "nanoseconds";
    qDebug()<<"Resulted string is:\n"<<
              qbr;
    qbr = QAESEncryption::RemovePadding(qbr, QAESEncryption::ZERO);
    qDebug()<<"Resulted string after removing training nulls is:\n"<<
              qbr;
    qDebug()<<"size input "<<line.size()<<"size output "<<qbr.size();
    timer2.start();
    QByteArray qbr2 = WinDecrypt( line, qbKey);
    qDebug() << "The slow operation took" << timer2.nsecsElapsed() << "nanoseconds";
    qDebug()<<"Resulted string in one move WinAPI  is\n"<<
              qbr2;
    wAPI_AES_ECB_Decryptor deca;
    timer2.start();
    qbr2 = deca.decrypt(line, qbKey);
    qDebug() << "Only decode operation took" << timer2.nsecsElapsed() << "nanoseconds";
    qDebug()<<"Resulted string in one move WinAPI  is\n"<<
              qbr2;
    qDebug()<<"Confirmation that internal objects of class are capable to decode again. Preferrably to use another key/text pair";
    timer2.start();
    qbr2 = deca.decrypt(line, qbKey);
    qDebug() << "Only decode second time operation took" << timer2.nsecsElapsed() << "nanoseconds";
    qDebug()<<"Resulted string in one move WinAPI  is\n"<<
              qbr2;

    return 0;
}
