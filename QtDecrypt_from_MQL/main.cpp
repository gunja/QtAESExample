#include <QFile>
#include <QByteArray>
#include <QDebug>
#include <stdlib.h>
#ifdef _WIN32
    #include "wapi_enc.h"
    #include "wapi_dec.h"
#endif
#include "qaesencryption.h"

#include <QElapsedTimer>

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
    qDebug() << "The Qt-Class [slow operation] took" << timer.nsecsElapsed() << "nanoseconds";
    qDebug()<<"Resulted string is:\n"<<
              qbr;
    qbr = QAESEncryption::RemovePadding(qbr, QAESEncryption::ZERO);
    qDebug()<<"Resulted string after removing training nulls is:\n"<<
              qbr;
    qDebug()<<"size input "<<line.size()<<"size output "<<qbr.size();
    timer2.start();
    QByteArray qbr2 = WinDecrypt( line, qbKey);
    qDebug() << "The All In One call to WIN API  [ appeared to be also slow operation] took" << timer2.nsecsElapsed() << "nanoseconds";
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

    qDebug()<<"\n\nStarting decryption testing ";
    QString message =  "Am Anfang schuf Gott Himmel und Erde.\n"
            "Und die Erde war wüst und leer, und Finsternis lag auf der Tiefe; und der Geist Gottes schwebte über dem Wasser.\n"
            "Und Gott sprach: Es werde Licht! Und es ward Licht. Und Gott sah, dass das Licht gut war. Da schied Gott das Licht von der Finsternis\n"
            "und nannte das Licht Tag und die Finsternis Nacht. Da ward aus Abend und Morgen der erste Tag.\n"
            "Und Gott sprach: Es werde eine Feste zwischen den Wassern, die da scheide zwischen den Wassern.\n"
            "Da machte Gott die Feste und schied das Wasser unter der Feste von dem Wasser über der Feste. Und es geschah so.\n"
            "Und Gott nannte die Feste Himmel. Da ward aus Abend und Morgen der zweite Tag.\n"
            "Und Gott sprach: Es sammle sich das Wasser unter dem Himmel an einem Ort, dass man das Trockene sehe. Und es geschah so.\n"
            "Und Gott nannte das Trockene Erde, und die Sammlung der Wasser nannte er Meer. Und Gott sah, dass es gut war.\n"
            "Und Gott sprach: Es lasse die Erde aufgehen Gras und Kraut, das Samen bringe, und fruchtbare Bäume, die ein jeder nach seiner Art Früchte tragen, in denen ihr Same ist auf der Erde. Und es geschah so.\n"
            "Und die Erde ließ aufgehen Gras und Kraut, das Samen bringt, ein jedes nach seiner Art, und Bäume, die da Früchte tragen, in denen ihr Same ist, ein jeder nach seiner Art. Und Gott sah, dass es gut war.\n"
            "Da ward aus Abend und Morgen der dritte Tag.\n"
            "Und Gott sprach: Es werden Lichter an der Feste des Himmels, die da scheiden Tag und Nacht. Sie seien Zeichen für Zeiten, Tage und Jahre\n"
            "und seien Lichter an der Feste des Himmels, dass sie scheinen auf die Erde. Und es geschah so.\n"
            "Und Gott machte zwei große Lichter: ein großes Licht, das den Tag regiere, und ein kleines Licht, das die Nacht regiere, dazu auch die Sterne.\n"
            "Und Gott setzte sie an die Feste des Himmels, dass sie schienen auf die Erde 18 und den Tag und die Nacht regierten und schieden Licht und Finsternis. Und Gott sah, dass es gut war.\n"
            "Da ward aus Abend und Morgen der vierte Tag.\n"
            "Und Gott sprach: Es wimmle das Wasser von lebendigem Getier, und Vögel sollen fliegen auf Erden unter der Feste des Himmels.\n"
            "Und Gott schuf große Seeungeheuer und alles Getier, das da lebt und webt, davon das Wasser wimmelt, ein jedes nach seiner Art, und alle gefiederten Vögel, einen jeden nach seiner Art. Und Gott sah, dass es gut war.\n"
            "Und Gott segnete sie und sprach: Seid fruchtbar und mehret euch und erfüllet das Wasser im Meer, und die Vögel sollen sich mehren auf Erden.\n"
            "Da ward aus Abend und Morgen der fünfte Tag.\n"
            "Und Gott sprach: Die Erde bringe hervor lebendiges Getier, ein jedes nach seiner Art: Vieh, Gewürm und Tiere des Feldes, ein jedes nach seiner Art. Und es geschah so.\n"
            "Und Gott machte die Tiere des Feldes, ein jedes nach seiner Art, und das Vieh nach seiner Art und alles Gewürm des Erdbodens nach seiner Art. Und Gott sah, dass es gut war.";
    qDebug()<<"Using text with lenght "<<message.toUtf8().length();
    wAPI_AES_ECB_Encryptor enca;
    QByteArray qbKey24 = qbKey.left(24); qbKey24.resize(32);
    QByteArray qbKey16 = qbKey.left(16); qbKey16.resize(32);

    timer2.start();
    QByteArray qbr_k32 = enca.encrypt(message.toUtf8(), qbKey );
    qint64 nanoEla = timer2.nsecsElapsed();
    qDebug()<<"Encryption with 32 bytes key took "<<nanoEla<<" ns and produced "<< qbr_k32.length()<<" bytes output";

    timer2.start();
    QByteArray qbr_k24 = enca.encrypt(message.toUtf8(), qbKey24 );
    nanoEla = timer2.nsecsElapsed();
    qDebug()<<"Encryption with 24 bytes key took "<<nanoEla<<" ns and produced "<< qbr_k24.length()<<" bytes output";

    timer2.start();
    QByteArray qbr_k16 = enca.encrypt(message.toUtf8(), qbKey16 );
    nanoEla = timer2.nsecsElapsed();
    qDebug()<<"Encryption with 16 bytes key took "<<nanoEla<<" ns and produced "<< qbr_k16.length()<<" bytes output";

    qDebug()<<"Checking of decryption";
    QByteArray decry32 = QAESEncryption::Decrypt(QAESEncryption::AES_256, QAESEncryption::ECB, qbr_k32, qbKey);
    decry32 = QAESEncryption::RemovePadding(decry32, QAESEncryption::ZERO);
    QString decrStr = QString::fromUtf8( decry32);
    if( decrStr != message ) {
        qDebug()<<"Decrypted string diverged from original:\n";
        qDebug()<<"Original: "<<message;
        qDebug()<<"Decrypted: "<<decrStr;
    }
    QByteArray decry24 = QAESEncryption::Decrypt(QAESEncryption::AES_256, QAESEncryption::ECB, qbr_k24, qbKey);
    decry24 = QAESEncryption::RemovePadding(decry24, QAESEncryption::ZERO);
    decrStr = QString::fromUtf8( decry24);
    if( decrStr == message ) {
        qDebug()<<"Decrypted string matches original (while should not):\n";
        qDebug()<<"Original: "<<message;
        qDebug()<<"Decrypted: "<<decrStr;
    }
    decry24 = QAESEncryption::Decrypt(QAESEncryption::AES_256, QAESEncryption::ECB, qbr_k24, qbKey24);
    decry24 = QAESEncryption::RemovePadding(decry24, QAESEncryption::ZERO);
    decrStr = QString::fromUtf8( decry24);
    if( decrStr != message ) {
        qDebug()<<"Decrypted string diverged from original:\n";
        qDebug()<<"Original: "<<message;
        qDebug()<<"Decrypted: "<<decrStr;
    }
    QByteArray decry16 = QAESEncryption::Decrypt(QAESEncryption::AES_256, QAESEncryption::ECB, qbr_k16, qbKey);
    decry16 = QAESEncryption::RemovePadding(decry16, QAESEncryption::ZERO);
    decrStr = QString::fromUtf8( decry16);
    if( decrStr == message ) {
        qDebug()<<"Decrypted string matches original (while should not):\n";
        qDebug()<<"Original: "<<message;
        qDebug()<<"Decrypted: "<<decrStr;
    }
    decry16 = QAESEncryption::Decrypt(QAESEncryption::AES_256, QAESEncryption::ECB, qbr_k16, qbKey16);
    decry16 = QAESEncryption::RemovePadding(decry16, QAESEncryption::ZERO);
    decrStr = QString::fromUtf8( decry16);
    if( decrStr != message ) {
        qDebug()<<"Decrypted string diverged from original:\n";
        qDebug()<<"Original: "<<message;
        qDebug()<<"Decrypted: "<<decrStr;
    }
    qDebug()<<"Done";

    return 0;
}
