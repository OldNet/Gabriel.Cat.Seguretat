using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Gabriel.Cat.Extension
{
    public enum TextEcrypt
    {
        Perdut
    }
   public static class StringEncrypt
    {
        
        public const char CharChangeDefault = '\n';
        #region CanNotDecrypt
        public static string EncryptNotReverse(this string password, PasswordEncrypt passwordEncrypt = PasswordEncrypt.Md5)
        {
            switch (passwordEncrypt)
            {
                case PasswordEncrypt.Md5: password = Serializar.GetBytes(password).Hash(); break;
                case PasswordEncrypt.Sha256: password = Serializar.GetBytes(password).SHA3(); break;
            }
            return password;
        }
        #endregion
        #region OneKey
        #region SobreCargaEncrypt
        public static string Encrypt(this string text, string password, DataEncrypt dataEncrypt = DataEncrypt.Cesar, LevelEncrypt level = LevelEncrypt.Normal, PasswordEncrypt passwordEncrypt = PasswordEncrypt.Nothing,Ordre order=Ordre.Consecutiu)
        {
        	if(string.IsNullOrEmpty(password))throw new ArgumentException("se requiere una password con longitud minima de un caracter");
            return Encrypt(text, Serializar.GetBytes(password), dataEncrypt, level, passwordEncrypt,order);
        }
        public static string Encrypt(this string text, byte[] password, DataEncrypt dataEncrypt = DataEncrypt.Cesar, LevelEncrypt level = LevelEncrypt.Normal, PasswordEncrypt passwordEncrypt = PasswordEncrypt.Nothing, Ordre order = Ordre.Consecutiu)
        {
        	if(password==null||password.Length==0)throw new ArgumentException("se requiere una password con longitud minima de un byte");
            return Encrypt(text, password.EncryptNotReverse(passwordEncrypt), dataEncrypt, level,order);
        }
        #endregion
        internal static string Encrypt(this string text, byte[] password, DataEncrypt dataEncrypt, LevelEncrypt level, Ordre order = Ordre.Consecutiu)
        {
            string textXifrat;
            switch (dataEncrypt)
            {
                default: textXifrat = Serializar.ToString(Serializar.GetBytes(text).Encrypt(password, dataEncrypt, level, order)); break;
            }
            return textXifrat;
        }
        #region SobreCargaEncrypt
        public static string Encrypt(this string text, string password, TextEcrypt dataEncrypt =TextEcrypt.Perdut, LevelEncrypt level = LevelEncrypt.Normal, PasswordEncrypt passwordEncrypt = PasswordEncrypt.Nothing, Ordre order = Ordre.Consecutiu)
        {
            if (string.IsNullOrEmpty(password)) throw new ArgumentException("se requiere una password con longitud minima de un caracter");
            return Encrypt(text, Serializar.GetBytes(password), dataEncrypt, level, passwordEncrypt, order);
        }
        public static string Encrypt(this string text, byte[] password, TextEcrypt dataEncrypt = TextEcrypt.Perdut, LevelEncrypt level = LevelEncrypt.Normal, PasswordEncrypt passwordEncrypt = PasswordEncrypt.Nothing, Ordre order = Ordre.Consecutiu)
        {
            if (password == null || password.Length == 0) throw new ArgumentException("se requiere una password con longitud minima de un byte");
            return Encrypt(text, password.EncryptNotReverse(passwordEncrypt), dataEncrypt, level, order);
        }
        #endregion
        internal static string Encrypt(this string text, byte[] password, TextEcrypt dataEncrypt, LevelEncrypt level, Ordre order = Ordre.Consecutiu)
        {
            string textXifrat;
            switch (dataEncrypt)
            {
                  case TextEcrypt.Perdut:
                       textXifrat = ComunEncryptDecryptPerdut(text, password, level, order, true);
                       break;
                default:throw new ArgumentOutOfRangeException();
            }
            return textXifrat;
        }
        #region SobreCargaDecrypt
        public static string Decrypt(this string text, string password, DataEncrypt dataEncrypt = DataEncrypt.Cesar, LevelEncrypt level = LevelEncrypt.Normal, PasswordEncrypt passwordEncrypt = PasswordEncrypt.Nothing, Ordre order = Ordre.Consecutiu)
        {
            if (string.IsNullOrEmpty(password))
				throw new ArgumentException("se requiere una password", "password");
            return Decrypt(text, Serializar.GetBytes(password), dataEncrypt, level, passwordEncrypt,order);
        }
        public static string Decrypt(this string text, byte[] password, DataEncrypt dataEncrypt = DataEncrypt.Cesar, LevelEncrypt level = LevelEncrypt.Normal, PasswordEncrypt passwordEncrypt = PasswordEncrypt.Nothing, Ordre order = Ordre.Consecutiu)
        {
            if(password==null||password.Length==0)throw new ArgumentException("se requiere una password con longitud minima de un byte");
            return Decrypt(text, password.EncryptNotReverse(passwordEncrypt), dataEncrypt, level,order);
        }
        #endregion
        internal static string Decrypt(this string text, byte[] password, DataEncrypt dataEncrypt, LevelEncrypt level, Ordre order = Ordre.Consecutiu)
        {
            string textDesxifrat;
            switch(dataEncrypt)
            {
                default:textDesxifrat= Serializar.ToString(Serializar.GetBytes(text).Decrypt(password, dataEncrypt, level, order));break;
            }
            return textDesxifrat;
        }
        #region SobreCargaDecrypt
        public static string Decrypt(this string text, string password, TextEcrypt dataEncrypt = TextEcrypt.Perdut, LevelEncrypt level = LevelEncrypt.Normal, PasswordEncrypt passwordEncrypt = PasswordEncrypt.Nothing, Ordre order = Ordre.Consecutiu)
        {
            if (string.IsNullOrEmpty(password))
                throw new ArgumentException("se requiere una password", "password");
            return Decrypt(text, Serializar.GetBytes(password), dataEncrypt, level, passwordEncrypt, order);
        }
        public static string Decrypt(this string text, byte[] password, TextEcrypt dataEncrypt = TextEcrypt.Perdut, LevelEncrypt level = LevelEncrypt.Normal, PasswordEncrypt passwordEncrypt = PasswordEncrypt.Nothing, Ordre order = Ordre.Consecutiu)
        {
            if (password == null || password.Length == 0) throw new ArgumentException("se requiere una password con longitud minima de un byte");
            return Decrypt(text, password.EncryptNotReverse(passwordEncrypt), dataEncrypt, level, order);
        }
        #endregion
        internal static string Decrypt(this string text, byte[] password, TextEcrypt dataEncrypt, LevelEncrypt level, Ordre order = Ordre.Consecutiu)
        {
            string textDesxifrat;
            switch (dataEncrypt)
            {
                 case TextEcrypt.Perdut:textDesxifrat = ComunEncryptDecryptPerdut(text, password, level, order, false);
                     break;
                default:throw new ArgumentOutOfRangeException();
            }
            return textDesxifrat;
        }
        #region CharsPerduts
        private static string ComunEncryptDecryptPerdut(string chars, byte[] password, LevelEncrypt level, Ordre order, bool toEncrypt)
        {
        

            unsafe
            {
                char* ptrChars;
                chars = new string(chars.ToCharArray());
                fixed (char* ptChars = chars)
                {
                    ptrChars = ptChars;
                    for (int i = 0, f = (int)level + 1; i < f; i++)//repito el proceso como nivel de seguridad :D
                    {
                        TractaPerdut(ptrChars, chars.Length, password, level, order, toEncrypt);//si descifra ira hacia atrás
                    }
                }

            }
            return chars;
        }

        private static unsafe void TractaPerdut(char* ptrChars,int lenght, byte[] password, LevelEncrypt level, Ordre order, bool leftToRight)
        {//de momento no va del todo bien...
            char aux;
            long posAux;
            int direccion = leftToRight ? 1 : -1;
            //falta probar
            for (long i = leftToRight ? 0 : lenght - 1, f = leftToRight ? lenght- 1 : 0; leftToRight ? i <= f : i >= f; i += direccion)
            {
                posAux = (ByteEncrypt.CalucloNumeroCirfrado(password, level, order, (int)i) + i) % lenght;
                aux = ptrChars[posAux];
                ptrChars[posAux] = ptrChars[i];
                ptrChars[i] = aux;
            }

        }
        #endregion
        #endregion
        #region MultiKey
        #region Escollir clau per caracter
        #region SobreCargaEncrypt
        public static string Encrypt(this string text, string[] passwords, DataEncrypt dataEncrypt = DataEncrypt.Cesar, PasswordEncrypt passwordEncrypt = PasswordEncrypt.Md5, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu, char charChange = CharChangeDefault)
        {
            return Encrypt(text, passwords, new DataEncrypt[] { dataEncrypt }, new PasswordEncrypt[] { passwordEncrypt }, level, escogerKey, charChange);
        }
        public static string Encrypt(this string text, string[] passwords, DataEncrypt[] dataEncrypt, PasswordEncrypt passwordEncrypt = PasswordEncrypt.Md5, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu, char charChange = CharChangeDefault)
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

        public static string Encrypt(this string text, byte[][] passwords, DataEncrypt dataEncrypt = DataEncrypt.Cesar, PasswordEncrypt passwordEncrypt = PasswordEncrypt.Md5, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu, char charChange = CharChangeDefault)
        {
            return Encrypt(text, passwords, new DataEncrypt[] { dataEncrypt }, new PasswordEncrypt[] { passwordEncrypt }, level, escogerKey, charChange);
        }
        public static string Encrypt(this string text, byte[][] passwords, DataEncrypt[] dataEncrypt, PasswordEncrypt passwordEncrypt = PasswordEncrypt.Md5, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu, char charChange = CharChangeDefault)
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
        public static string Decrypt(this string text, string[] passwords, DataEncrypt dataEncrypt = DataEncrypt.Cesar, PasswordEncrypt passwordEncrypt = PasswordEncrypt.Md5, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu, char charChange = CharChangeDefault)
        {
            return Decrypt(text, passwords, new DataEncrypt[] { dataEncrypt }, new PasswordEncrypt[] { passwordEncrypt }, level, escogerKey, charChange);
        }
        public static string Decrypt(this string text, string[] passwords, DataEncrypt[] dataEncrypt, PasswordEncrypt passwordEncrypt = PasswordEncrypt.Md5, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu, char charChange = CharChangeDefault)
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
        public static string Decrypt(this string text, byte[][] passwords, DataEncrypt dataEncrypt = DataEncrypt.Cesar, PasswordEncrypt passwordEncrypt = PasswordEncrypt.Md5, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu, char charChange = CharChangeDefault)
        {
            return Decrypt(text, passwords, new DataEncrypt[] { dataEncrypt }, new PasswordEncrypt[] { passwordEncrypt }, level, escogerKey, charChange);
        }
        public static string Decrypt(this string text, byte[][] passwords, DataEncrypt[] dataEncrypt, PasswordEncrypt passwordEncrypt = PasswordEncrypt.Md5, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu, char charChange = CharChangeDefault)
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
