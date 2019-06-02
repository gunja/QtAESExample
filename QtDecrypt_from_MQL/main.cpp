#include "qaesencryption.h"
#include <QFile>
#include <QByteArray>
#include <QDebug>
#include <stdlib.h>

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
    QByteArray qbr = QAESEncryption::Decrypt(QAESEncryption::AES_256, QAESEncryption::ECB,
                           line, qbKey);
    qDebug()<<"Resulted string is:\n"<<
              qbr;
    qbr = QAESEncryption::RemovePadding(qbr, QAESEncryption::ZERO);
    qDebug()<<"Resulted string after removing training nulls is:\n"<<
              qbr;
    QByteArray qbr2 = QAESEncryption::Decrypt(QAESEncryption::AES_256, QAESEncryption::ECB,
                           line, qbKey, NULL, QAESEncryption::ZERO );
    qDebug()<<"Resulted string in one move ZERO is\n"<<
              qbr2;
    return 0;
}
