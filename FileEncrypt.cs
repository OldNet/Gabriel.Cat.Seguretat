using Gabriel.Cat.Extension;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Gabriel.Cat.Seguretat
{
    /// <summary>
    /// Es una clases de extension para cifrar archivos sin cargarlos enteramente a la ram, naturalmente al no usar pointers irá mas lento :) pero podrá con los archivos grandes sin saturar la ram :D
    /// </summary>
   public static class FileEncrypt
    {
        #region SobreCarga Encrypt and Comun
        public static FileInfo Encrypt(this FileInfo fileToEncryp, string password,bool outputInADirefetnFile=false, DataEncrypt dataEncrypt = DataEncrypt.Cesar, LevelEncrypt level = LevelEncrypt.Normal, PasswordEncrypt passwordEncrypt = PasswordEncrypt.Nothing, Ordre order = Ordre.Consecutiu)
        {

            if (string.IsNullOrEmpty(password)) throw new ArgumentException("se requiere una password con longitud minima de un caracter");
            return Encrypt(fileToEncryp, Serializar.GetBytes(password),outputInADirefetnFile, dataEncrypt, level, passwordEncrypt, order);
        }
        public static FileInfo Encrypt(this FileInfo fileToEncryp, byte[] password, bool outputInADirefetnFile = false, DataEncrypt dataEncrypt = DataEncrypt.Cesar, LevelEncrypt level = LevelEncrypt.Normal, PasswordEncrypt passwordEncrypt = PasswordEncrypt.Nothing, Ordre order = Ordre.Consecutiu)
        {
            if (password == null || password.Length == 0) throw new ArgumentException("se requiere una password con longitud minima de un byte");
            return ComunEncryptDecrypt(fileToEncryp, password.EncryptNotReverse(passwordEncrypt), dataEncrypt, level, order, outputInADirefetnFile);
        }

        internal static FileInfo ComunEncryptDecrypt(FileInfo fileToEncrypOrDecrypt, byte[] password, DataEncrypt dataEncrypt, LevelEncrypt level, Ordre order, bool outputInADirefetnFile = false,bool encrypt=true)
        {
            string pathTemp=null,pathFinal;
            FileStream fsFileToEncrypt = new FileStream(fileToEncrypOrDecrypt.FullName, FileMode.Open, outputInADirefetnFile ? FileAccess.Read : FileAccess.ReadWrite);
            FileStream fsFileOutPut=null;
            StreamReader srFileToEncrypt=new StreamReader(fsFileToEncrypt);
            StreamWriter swFilteOutputEncrypted;
            if (outputInADirefetnFile)
            {
                pathTemp = Path.GetTempFileName();
                fsFileOutPut = new FileStream(pathTemp, FileMode.OpenOrCreate, FileAccess.Write);
                swFilteOutputEncrypted = new StreamWriter(fsFileOutPut);
            }
            else swFilteOutputEncrypted = new StreamWriter(fsFileToEncrypt);

            //encrypto los datos :D
            if(encrypt)
            {
                ComunEncryptDecrypt(srFileToEncrypt, swFilteOutputEncrypted, password, dataEncrypt, level, order);
            }
            else
            {
                Dencrypt(srFileToEncrypt, swFilteOutputEncrypted, password, dataEncrypt, level, order);
            }

            if (outputInADirefetnFile)
            {
                pathFinal = fileToEncrypOrDecrypt.Directory.FullName + Path.DirectorySeparatorChar + Path.GetFileNameWithoutExtension(fileToEncrypOrDecrypt.FullName) + "." + DateTime.Now.Ticks + (encrypt? "-Encrypted.":" -Decrypted") + Path.GetExtension(fileToEncrypOrDecrypt.FullName);
                File.Move(pathTemp, pathFinal);

            }
            else pathFinal = fileToEncrypOrDecrypt.FullName;

            swFilteOutputEncrypted.Close();
            srFileToEncrypt.Close();

            fsFileToEncrypt.Close();

            if (outputInADirefetnFile)
                fsFileOutPut.Close();

            return new FileInfo(pathFinal);
        }
        public static void Encrypt(this StreamReader srIn, StreamWriter swOut, string password,  DataEncrypt dataEncrypt = DataEncrypt.Cesar, LevelEncrypt level = LevelEncrypt.Normal, PasswordEncrypt passwordEncrypt = PasswordEncrypt.Nothing, Ordre order = Ordre.Consecutiu, bool startPosition0 = true)
        {

            if (string.IsNullOrEmpty(password)) throw new ArgumentException("se requiere una password con longitud minima de un caracter");
            Encrypt(srIn,swOut, Serializar.GetBytes(password), dataEncrypt, level, passwordEncrypt, order,startPosition0);
        }
        public static void Encrypt(this StreamReader srIn, StreamWriter swOut, byte[] password, DataEncrypt dataEncrypt = DataEncrypt.Cesar, LevelEncrypt level = LevelEncrypt.Normal, PasswordEncrypt passwordEncrypt = PasswordEncrypt.Nothing, Ordre order = Ordre.Consecutiu, bool startPosition0 = true)
        {
            if (password == null || password.Length == 0) throw new ArgumentException("se requiere una password con longitud minima de un byte");
            ComunEncryptDecrypt(srIn,swOut,true, password.EncryptNotReverse(passwordEncrypt), dataEncrypt, level, order,startPosition0);
        }
        #endregion
        internal static void ComunEncryptDecrypt(StreamReader srIn, StreamWriter swOut,bool encrypt, byte[] password, DataEncrypt dataEncrypt, LevelEncrypt level, Ordre order, bool startPosition0 = true)
        {//si hay nuevos metodos se toca aqui solo :D
            if (!srIn.BaseStream.CanRead &&(startPosition0&& srIn.BaseStream.CanSeek))
                throw new ArgumentException("can't read or seek stream", "srIn");
            if (!swOut.BaseStream.CanWrite && (startPosition0 && swOut.BaseStream.CanSeek))
                throw new ArgumentException("can't write or seek stream", "swOut");
            long posicionSr = srIn.BaseStream.Position, posicionSw = swOut.BaseStream.Position;
            if (startPosition0)
            {
                srIn.BaseStream.Position = 0;
                swOut.BaseStream.Position = 0;
            }
            if (encrypt)
            {
                switch (dataEncrypt)
                {
                    case DataEncrypt.Cesar: EncryptCesar(srIn, swOut, password, level, order); break;
                    case DataEncrypt.Disimulat: EncryptDisimulat(srIn, swOut, password, level, order); break;
                    case DataEncrypt.Perdut: EncryptPerdut(srIn, swOut, password, level, order); break;
                    default: throw new ArgumentOutOfRangeException("dataEncrypt");
                }
            }
            else
            {
                switch (dataEncrypt)
                {
                    case DataEncrypt.Cesar: DencryptCesar(srIn, swOut, password, level, order); break;
                    case DataEncrypt.Disimulat: DencryptDisimulat(srIn, swOut, password, level, order); break;
                    case DataEncrypt.Perdut: DencryptPerdut(srIn, swOut, password, level, order); break;
                    default: throw new ArgumentOutOfRangeException("dataEncrypt");
                }
            }
            if (startPosition0)
            {
                srIn.BaseStream.Position = posicionSr;
                swOut.BaseStream.Position = posicionSw;
            }
        }

        #region SobreCarga Decrypt
        public static FileInfo Decrypt(this FileInfo fileToEncryp, string password, bool outputInADirefetnFile = false, DataEncrypt dataEncrypt = DataEncrypt.Cesar, LevelEncrypt level = LevelEncrypt.Normal, PasswordEncrypt passwordEncrypt = PasswordEncrypt.Nothing, Ordre order = Ordre.Consecutiu)
        {

            if (string.IsNullOrEmpty(password)) throw new ArgumentException("se requiere una password con longitud minima de un caracter");
            return Decrypt(fileToEncryp, Serializar.GetBytes(password), outputInADirefetnFile, dataEncrypt, level, passwordEncrypt, order);
        }
        public static FileInfo Decrypt(this FileInfo fileToDecrypt, byte[] password, bool outputInADirefetnFile = false, DataEncrypt dataEncrypt = DataEncrypt.Cesar, LevelEncrypt level = LevelEncrypt.Normal, PasswordEncrypt passwordEncrypt = PasswordEncrypt.Nothing, Ordre order = Ordre.Consecutiu)
        {
            if (password == null || password.Length == 0) throw new ArgumentException("se requiere una password con longitud minima de un byte");
            return ComunEncryptDecrypt(fileToDecrypt, password.EncryptNotReverse(passwordEncrypt), dataEncrypt, level, order, outputInADirefetnFile);
        }
        public static void Dencrypt(this StreamReader srIn, StreamWriter swOut, string password, DataEncrypt dataEncrypt = DataEncrypt.Cesar, LevelEncrypt level = LevelEncrypt.Normal, PasswordEncrypt passwordEncrypt = PasswordEncrypt.Nothing, Ordre order = Ordre.Consecutiu, bool startPosition0 = true)
        {

            if (string.IsNullOrEmpty(password)) throw new ArgumentException("se requiere una password con longitud minima de un caracter");
            Dencrypt(srIn, swOut, Serializar.GetBytes(password), dataEncrypt, level, passwordEncrypt, order,startPosition0);
        }
        public static void Dencrypt(this StreamReader srIn, StreamWriter swOut, byte[] password, DataEncrypt dataEncrypt = DataEncrypt.Cesar, LevelEncrypt level = LevelEncrypt.Normal, PasswordEncrypt passwordEncrypt = PasswordEncrypt.Nothing, Ordre order = Ordre.Consecutiu, bool startPosition0 = true)
        {
            if (password == null || password.Length == 0) throw new ArgumentException("se requiere una password con longitud minima de un byte");
            ComunEncryptDecrypt(srIn, swOut,false, password.EncryptNotReverse(passwordEncrypt), dataEncrypt, level, order,startPosition0);
        }
        #endregion


      
        #region EncryptMethods falta testing

        private static void EncryptCesar(StreamReader srIn, StreamWriter swOut, byte[] password, LevelEncrypt level, Ordre order)
        {
            int sumaCesar;
            for (long i = srIn.BaseStream.Position, pos = 0; i < srIn.BaseStream.Length; i++, pos += 2)
            {
                sumaCesar =ByteEncrypt.CalucloNumeroCirfrado(password, level, order,(int) pos);
                swOut.Write((byte)((srIn.Read() + sumaCesar) % (byte.MaxValue + 1)));
            }
        }
        private static void DencryptCesar(StreamReader srIn, StreamWriter swOut, byte[] password, LevelEncrypt level, Ordre order)
        {
            int restaCesar;
            int preByte;
            for (int i = 0, pos = 0; i < srIn.BaseStream.Length; i++, pos += 2)
            {
                restaCesar =ByteEncrypt.CalucloNumeroCirfrado(password, level, order, pos);
                preByte = srIn.Read() - restaCesar;

                if (preByte < byte.MinValue)
                {
                    preByte *= -1;
                    preByte %= (byte.MaxValue + 1);
                    preByte *= -1;
                    if (preByte < byte.MinValue)
                        preByte += byte.MaxValue + 1;

                }

                //tengo lo que le han puesto de mas y tengo que quitarselo teniendo en cuenta que cuando llegue a 0 tiene que seguir 255
                swOut.Write((byte)preByte);
            }
        }
        private static void EncryptDisimulat(StreamReader srIn, StreamWriter swOut, byte[] password, LevelEncrypt level, Ordre order)
        {//mirar de hacerlo async a ver si funciona bien...o hace de las suyas...
            int numBytesRandom;
            for (long i = srIn.BaseStream.Position; i < srIn.BaseStream.Length; i++)
            {
                //recorro la array de bytes y pongo los bytes nuevos que tocan
                numBytesRandom =ByteEncrypt.CalucloNumeroCirfrado(password, level, order,i);
                for (int j = 0; j < numBytesRandom; j++)
                {
                   swOut.Write((byte)MiRandom.Next(byte.MaxValue));
                }
                swOut.Write((byte)srIn.Read());
            }
        }
        private static void DencryptDisimulat(StreamReader srIn, StreamWriter swOut, byte[] password, LevelEncrypt level, Ordre order)
        {
            for (long i = srIn.BaseStream.Position+ ByteEncrypt.CalucloNumeroCirfrado(password, level, order, srIn.BaseStream.Position); i < srIn.BaseStream.Length; i+= ByteEncrypt.CalucloNumeroCirfrado(password, level, order, i))
            {
                srIn.BaseStream.Position = i;
                swOut.Write((byte)srIn.Read());
            }
        }
       private static void EncryptPerdut(StreamReader srIn, StreamWriter swOut, byte[] password, LevelEncrypt level, Ordre order)
        {
            
            ComunPerdut(srIn, swOut,password,level,order,true);
           
        }

        private static void ComunPerdut(StreamReader srIn, StreamWriter swOut, byte[] password, LevelEncrypt level, Ordre order, bool encrypt)
        {//se tiene que pensar :D mirar si funciona porque no estoy del todo seguro 
            if (!swOut.BaseStream.CanRead || !swOut.BaseStream.CanSeek)
                throw new ArgumentException("Stream out can't read or seek");
            byte aux;
            int posAux;
            int direccion = encrypt ? 1 : -1;
            long posicionInicioOut = swOut.BaseStream.Position;
            StreamReader srOut = new StreamReader(swOut.BaseStream);
            BinaryWriter brOut = new BinaryWriter(swOut.BaseStream);
           
            //copio los datos
            for (long i = srIn.BaseStream.Position; i < srIn.BaseStream.Length; i++)
                swOut.Write(srIn.Read());
            swOut.BaseStream.Position = posicionInicioOut;
     
            for (int j = 0, f = (int)level + 1; j < f; j++)//repito el proceso como nivel de seguridad :D
            {

                for (int i =(int)( encrypt ? posicionInicioOut : swOut.BaseStream.Length - 1), k =(int) (encrypt ? swOut.BaseStream.Length - 1 : posicionInicioOut),total=Math.Abs(i-f); encrypt ? i <= k : i >= k; i += direccion)
                {
                    posAux = (ByteEncrypt.CalucloNumeroCirfrado(password, level, order, i) + i) % total;
                    srOut.BaseStream.Position = posAux;
                    aux =(byte) srOut.Read();
                    srOut.BaseStream.Position = i;
                    brOut.Seek(i, SeekOrigin.Begin);
                    brOut.Write((byte)srOut.Read()); //tengo que quitar ese byte de la stream

                    brOut.Seek(posAux,SeekOrigin.Begin);
                    brOut.Write(aux);
                }
            }
        }

        private static void DencryptPerdut(StreamReader srIn, StreamWriter swOut, byte[] password, LevelEncrypt level, Ordre order)
        {
            ComunPerdut(srIn, swOut, password, level, order, false);
        }

       

       
        #endregion
    }
}
