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

        internal static FileInfo ComunEncryptDecrypt(FileInfo fileToEncryp, byte[] password, DataEncrypt dataEncrypt, LevelEncrypt level, Ordre order, bool outputInADirefetnFile = false,bool encrypt=true)
        {
            string pathTemp=null,pathFinal;
            FileStream fsFileToEncrypt = new FileStream(fileToEncryp.FullName, FileMode.Open, outputInADirefetnFile ? FileAccess.Read : FileAccess.ReadWrite);
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
                Encrypt(srFileToEncrypt, swFilteOutputEncrypted, password, dataEncrypt, level, order);
            }
            else
            {
                Dencrypt(srFileToEncrypt, swFilteOutputEncrypted, password, dataEncrypt, level, order);
            }

            if (outputInADirefetnFile)
            {
                pathFinal = fileToEncryp.Directory.FullName + Path.DirectorySeparatorChar + Path.GetFileNameWithoutExtension(fileToEncryp.FullName) + "." + DateTime.Now.Ticks + (encrypt? "-Encrypted.":" -Decrypted") + Path.GetExtension(fileToEncryp.FullName);
                File.Move(pathTemp, pathFinal);

            }
            else pathFinal = fileToEncryp.FullName;

            swFilteOutputEncrypted.Close();
            srFileToEncrypt.Close();

            fsFileToEncrypt.Close();

            if (outputInADirefetnFile)
                fsFileOutPut.Close();

            return new FileInfo(pathFinal);
        }

        internal static void Encrypt(StreamReader srFileToEncrypt, StreamWriter swFilteOutputEncrypted, byte[] password, DataEncrypt dataEncrypt, LevelEncrypt level, Ordre order)
        {
            throw new NotImplementedException();
        }
        internal static void Dencrypt(StreamReader srFileEncrypted, StreamWriter swFilteOutputDencrypted, byte[] password, DataEncrypt dataEncrypt, LevelEncrypt level, Ordre order)
        {
            throw new NotImplementedException();
        }
    }
}
