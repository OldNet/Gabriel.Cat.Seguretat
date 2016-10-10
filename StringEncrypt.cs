using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Gabriel.Cat.Extension
{
   public static class StringEncrypt
    {
        public const char CharChangeDefault = '\n';
        #region CanNotDecrypt
        public static string EncryptNotReverse(this string password, PasswordEncrypt passwordEncrypt = PasswordEncrypt.Hash)
        {
            switch (passwordEncrypt)
            {
                case PasswordEncrypt.Hash: password = Serializar.GetBytes(password).Hash(); break;
                case PasswordEncrypt.Sha3: password = Serializar.GetBytes(password).SHA3(); break;
            }
            return password;
        }
        #endregion
        #region OneKey
        #region SobreCargaEncrypt
        public static string Encrypt(this string text, string password, DataEncrypt dataEncrypt = DataEncrypt.Cesar, LevelEncrypt level = LevelEncrypt.Normal, PasswordEncrypt passwordEncrypt = PasswordEncrypt.Nothing,Ordre order=Ordre.Consecutiu)
        {
            if (password == null) password = "";
            return Encrypt(text, Serializar.GetBytes(password), dataEncrypt, level, passwordEncrypt,order);
        }
        public static string Encrypt(this string text, byte[] password, DataEncrypt dataEncrypt = DataEncrypt.Cesar, LevelEncrypt level = LevelEncrypt.Normal, PasswordEncrypt passwordEncrypt = PasswordEncrypt.Nothing, Ordre order = Ordre.Consecutiu)
        {
            return Encrypt(text, password, dataEncrypt, level, passwordEncrypt,order);
        }
        #endregion
        internal static string Encrypt(this string text, byte[] password, DataEncrypt dataEncrypt, LevelEncrypt level, Ordre order = Ordre.Consecutiu)
        {
            return Serializar.ToString(Serializar.GetBytes(text).Encrypt(password, dataEncrypt, level,order));
        }

        #region SobreCargaDecrypt
        public static string Decrypt(this string text, string password, DataEncrypt dataEncrypt = DataEncrypt.Cesar, LevelEncrypt level = LevelEncrypt.Normal, PasswordEncrypt passwordEncrypt = PasswordEncrypt.Nothing, Ordre order = Ordre.Consecutiu)
        {
            if (password == null) password = "";
            return Decrypt(text, Serializar.GetBytes(password), dataEncrypt, level, passwordEncrypt,order);
        }
        public static string Decrypt(this string text, byte[] password, DataEncrypt dataEncrypt = DataEncrypt.Cesar, LevelEncrypt level = LevelEncrypt.Normal, PasswordEncrypt passwordEncrypt = PasswordEncrypt.Nothing, Ordre order = Ordre.Consecutiu)
        {
            if (password == null) password = new byte[0];
            return Decrypt(text, password, dataEncrypt, level, passwordEncrypt,order);
        }
        #endregion
        internal static string Decrypt(this string text, byte[] password, DataEncrypt dataEncrypt, LevelEncrypt level, Ordre order = Ordre.Consecutiu)
        {
            return Serializar.ToString(Serializar.GetBytes(text).Decrypt(password, dataEncrypt, level, order));
        }

        #endregion
        #region MultiKey
        #region Escollir clau per caracter
        #region SobreCargaEncrypt
        public static string Encrypt(this string text, string[] passwords, DataEncrypt dataEncrypt = DataEncrypt.Cesar, PasswordEncrypt passwordEncrypt = PasswordEncrypt.Hash, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu, char charChange = CharChangeDefault)
        {
            return Encrypt(text, passwords, new DataEncrypt[] { dataEncrypt }, new PasswordEncrypt[] { passwordEncrypt }, level, escogerKey, charChange);
        }
        public static string Encrypt(this string text, string[] passwords, DataEncrypt[] dataEncrypt, PasswordEncrypt passwordEncrypt = PasswordEncrypt.Hash, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu, char charChange = CharChangeDefault)
        {
            return Encrypt(text, passwords, dataEncrypt, new PasswordEncrypt[] { passwordEncrypt }, level, escogerKey, charChange);
        }
        public static string Encrypt(this string text, string[] passwords, PasswordEncrypt[] passwordEncrypt, DataEncrypt dataEncrypt = DataEncrypt.Cesar, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu, char charChange = CharChangeDefault)
        {
            return Encrypt(text, passwords, new DataEncrypt[] { dataEncrypt }, passwordEncrypt, level, escogerKey, charChange);
        }
        public static string Encrypt(this string text, string[] passwords, DataEncrypt[] dataEncrypt, PasswordEncrypt[] passwordEncrypt, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu, char charChange = CharChangeDefault)
        {
            if (passwords == null || dataEncrypt == null || passwordEncrypt == null) throw new ArgumentNullException();
            List<byte[]> passwordBytes = new List<byte[]>();
            for (int i = 0; i < passwords.Length; i++)
                passwordBytes.Add(Serializar.GetBytes(passwords[i]));
            return Encrypt(text, passwordBytes.ToArray(), dataEncrypt, passwordEncrypt, level, escogerKey, charChange);
        }

        public static string Encrypt(this string text, byte[][] passwords, DataEncrypt dataEncrypt = DataEncrypt.Cesar, PasswordEncrypt passwordEncrypt = PasswordEncrypt.Hash, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu, char charChange = CharChangeDefault)
        {
            return Encrypt(text, passwords, new DataEncrypt[] { dataEncrypt }, new PasswordEncrypt[] { passwordEncrypt }, level, escogerKey, charChange);
        }
        public static string Encrypt(this string text, byte[][] passwords, DataEncrypt[] dataEncrypt, PasswordEncrypt passwordEncrypt = PasswordEncrypt.Hash, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu, char charChange = CharChangeDefault)
        {
            return Encrypt(text, passwords, dataEncrypt, new PasswordEncrypt[] { passwordEncrypt }, level, escogerKey, charChange);
        }
        public static string Encrypt(this string text, byte[][] passwords, PasswordEncrypt[] passwordEncrypt, DataEncrypt dataEncrypt = DataEncrypt.Cesar, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu, char charChange = CharChangeDefault)
        {
            return Encrypt(text, passwords, new DataEncrypt[] { dataEncrypt }, passwordEncrypt, level, escogerKey, charChange);
        }
        #endregion
        public static string Encrypt(this string text, byte[][] passwords, DataEncrypt[] dataEncrypt, PasswordEncrypt[] passwordEncrypt, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu, char charChange = CharChangeDefault)
        {
            //mirar que no de error los bytes devueltos tienen que ser pares...
            return Serializar.ToString(Serializar.GetBytes(text).Encrypt(passwords,Serializar.GetBytes(charChange), dataEncrypt,passwordEncrypt, level, escogerKey));
        }
        #region SobreCargaDecrypt
        public static string Decrypt(this string text, string[] passwords, DataEncrypt dataEncrypt = DataEncrypt.Cesar, PasswordEncrypt passwordEncrypt = PasswordEncrypt.Hash, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu, char charChange = CharChangeDefault)
        {
            return Decrypt(text, passwords, new DataEncrypt[] { dataEncrypt }, new PasswordEncrypt[] { passwordEncrypt }, level, escogerKey, charChange);
        }
        public static string Decrypt(this string text, string[] passwords, DataEncrypt[] dataEncrypt, PasswordEncrypt passwordEncrypt = PasswordEncrypt.Hash, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu, char charChange = CharChangeDefault)
        {
            return Encrypt(text, passwords, dataEncrypt, new PasswordEncrypt[] { passwordEncrypt }, level, escogerKey, charChange);
        }
        public static string Decrypt(this string text, string[] passwords, PasswordEncrypt[] passwordEncrypt, DataEncrypt dataEncrypt = DataEncrypt.Cesar, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu, char charChange = CharChangeDefault)
        {
            return Decrypt(text, passwords, new DataEncrypt[] { dataEncrypt }, passwordEncrypt, level, escogerKey, charChange);
        }
        public static string Decrypt(this string text, string[] passwords, DataEncrypt[] dataEncrypt, PasswordEncrypt[] passwordEncrypt, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu, char charChange = CharChangeDefault)
        {
            if (passwords == null || dataEncrypt == null || passwordEncrypt == null) throw new ArgumentNullException();
            List<byte[]> passwordBytes = new List<byte[]>();
            for (int i = 0; i < passwords.Length; i++)
                passwordBytes.Add(Serializar.GetBytes(passwords[i]));
            return Decrypt(text, passwordBytes.ToArray(), dataEncrypt, passwordEncrypt, level, escogerKey, charChange);
        }
        public static string Decrypt(this string text, byte[][] passwords, DataEncrypt dataEncrypt = DataEncrypt.Cesar, PasswordEncrypt passwordEncrypt = PasswordEncrypt.Hash, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu, char charChange = CharChangeDefault)
        {
            return Decrypt(text, passwords, new DataEncrypt[] { dataEncrypt }, new PasswordEncrypt[] { passwordEncrypt }, level, escogerKey, charChange);
        }
        public static string Decrypt(this string text, byte[][] passwords, DataEncrypt[] dataEncrypt, PasswordEncrypt passwordEncrypt = PasswordEncrypt.Hash, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu, char charChange = CharChangeDefault)
        {
            return Decrypt(text, passwords, dataEncrypt, new PasswordEncrypt[] { passwordEncrypt }, level, escogerKey, charChange);
        }
        public static string Decrypt(this string text, byte[][] passwords, PasswordEncrypt[] passwordEncrypt, DataEncrypt dataEncrypt = DataEncrypt.Cesar, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu, char charChange = CharChangeDefault)
        {
            return Decrypt(text, passwords, new DataEncrypt[] { dataEncrypt }, passwordEncrypt, level, escogerKey, charChange);
        }
        #endregion
        public static string Decrypt(this string text, byte[][] passwords, DataEncrypt[] dataEncrypt, PasswordEncrypt[] passwordEncrypt, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu, char charChange = CharChangeDefault)
        {
            //mirar que no de error los bytes devueltos tienen que ser pares...
            return Serializar.ToString(Serializar.GetBytes(text).Decrypt(passwords, Serializar.GetBytes(charChange), dataEncrypt, passwordEncrypt, level, escogerKey));
        }

        #endregion
        #endregion
    }
}
