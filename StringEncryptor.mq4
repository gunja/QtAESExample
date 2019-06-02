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
//--- �������� �������
   if(count<0 || count>ArraySize(arr))
      count=ArraySize(arr);
//--- �������������� � ����������������� ������
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
//--- ���������� ����� ����������
   StringToCharArray(keystr,key);
//--- ���������� ��������� ������� src[]
   StringToCharArray(text,src);
//--- ����� �������� ������
   PrintFormat("Initial data: size=%d, string='%s'",ArraySize(src),CharArrayToString(src));
   PrintFormat("Key data: size=%d, string='%s'",ArraySize(key),CharArrayToString(key));
//--- ���������� ������� src[] ������ CRYPT_AES256 ���������� AES � ������ 256 ��� (32 �����)
   int res=CryptEncode(CRYPT_AES256,src,key,dst);
//--- �������� ���������� ����������
ResetLastError();
   if(res>0)
     {
      //--- ����� ����������� ������
      PrintFormat("Encoded data: size=%d %s",res,ArrayToHex(dst));
      //also writing to file encoded string:
      int fd = FileOpen( "mql_CPP_crypted.tx", FILE_WRITE | FILE_BIN );
      if ( fd != 0 )
         PrintFormat("�� ������� ������� ���� ��� ������ = %d",GetLastError());
      // no check for file accurate
      for(int i =0; i < ArraySize(dst); ++i) {
         FileWriteInteger( fd, dst[i], CHAR_VALUE );
      }
      FileFlush(fd);
      FileClose( fd);
      //--- ����������� ������ ������� dst[] ������� DES � 56-������ ������ key[]
      res=CryptDecode(CRYPT_AES256,dst,key,src);
      //--- �������� ����������
      if(res>0)
        {
         //--- ����� ������������� ������
         PrintFormat("Decoded data: size=%d, string='%s'",ArraySize(src),CharArrayToString(src));
        }
      else
         Print("������ � CryptDecode. ��� ������=",GetLastError());
     }
   else
      Print("������ � CryptEncode. ��� ������=",GetLastError());
  }