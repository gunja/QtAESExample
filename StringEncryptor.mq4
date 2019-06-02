//+------------------------------------------------------------------+
//|                                              StringEncryptor.mq4 |
//|                        Copyright 2019, MetaQuotes Software Corp. |
//|                                             https://www.mql5.com |
//+------------------------------------------------------------------+
#property copyright "Copyright 2019, MetaQuotes Software Corp."
#property link      "https://www.mql5.com"
#property version   "1.00"
#property strict
//+------------------------------------------------------------------+
//| ArrayToHex                                                       |
//+------------------------------------------------------------------+
string ArrayToHex(uchar &arr[],int count=-1)
  {
   string res="";
//--- проверка размера
   if(count<0 || count>ArraySize(arr))
      count=ArraySize(arr);
//--- преобразование в шестнадцатиричную строку
   for(int i=0; i<count; i++)
      res+=StringFormat("%.2X",arr[i]);
//---
   return(res);
  }
//+------------------------------------------------------------------+
//| Script program start function                                    |
//+------------------------------------------------------------------+
void OnStart()
  {
   string text  ="The quick brown fox jumps over the lazy dog\nAnd makes it\nAgain and again and again";
   string keystr="Some Cool Password1234567890-1234"; // should be 32 bytes
   uchar src[],dst[],key[];
//--- подготовка ключа шифрования
   StringToCharArray(keystr,key);
//--- подготовка исходного массива src[]
   StringToCharArray(text,src);
//--- вывод исходных данных
   PrintFormat("Initial data: size=%d, string='%s'",ArraySize(src),CharArrayToString(src));
   PrintFormat("Key data: size=%d, string='%s'",ArraySize(key),CharArrayToString(key));
//--- шифрование массива src[] методо CRYPT_AES256 Шифрование AES с ключом 256 бит (32 байта)
   int res=CryptEncode(CRYPT_AES256,src,key,dst);
//--- проверка результата шифрования
ResetLastError();
   if(res>0)
     {
      //--- вывод шифрованных данных
      PrintFormat("Encoded data: size=%d %s",res,ArrayToHex(dst));
      //also writing to file encoded string:
      int fd = FileOpen( "mql_CPP_crypted.tx", FILE_WRITE | FILE_BIN );
      if ( fd != 0 )
         PrintFormat("Не удалось открыть файл Код ошибки = %d",GetLastError());
      // no check for file accurate
      for(int i =0; i < ArraySize(dst); ++i) {
         FileWriteInteger( fd, dst[i], CHAR_VALUE );
      }
      FileFlush(fd);
      FileClose( fd);
      //--- расшифровка данных массива dst[] методом DES с 56-битным ключом key[]
      res=CryptDecode(CRYPT_AES256,dst,key,src);
      //--- проверка результата
      if(res>0)
        {
         //--- вывод дешифрованных данных
         PrintFormat("Decoded data: size=%d, string='%s'",ArraySize(src),CharArrayToString(src));
        }
      else
         Print("Ошибка в CryptDecode. Код ошибки=",GetLastError());
     }
   else
      Print("Ошибка в CryptEncode. Код ошибки=",GetLastError());
  }