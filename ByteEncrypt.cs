using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
namespace Gabriel.Cat.Extension
{
    
    #region EnumCommunEncrypt
    public enum DataEncrypt
    {
        Disimulat,
        Cesar
    }
    public enum PasswordEncrypt
    {
        Hash,
        Sha3,
        Nothing
    }
    public enum LevelEncrypt
    {
        //la solucion al problema :D
        //los metodos tienen que cifrar teniendo en cuenta que un char son dos bytes y que byte[] puede ser impar y para que char no me de problema tiene que ser par siempre!!
        //poner valores par :) asi siempre sera par el cambio :D
        Lowest,
        Low=2,
        Normal=4,
        High=8,
        Highest=16
    }
#endregion
    public static class ByteEncrypt
    {
        private delegate byte[] MetodoMultiKey(byte[] data, byte[] password, DataEncrypt dataEncrypt, PasswordEncrypt passwordEncrypt, LevelEncrypt level,Ordre order);
        public static readonly byte[] BytesChangeDefault = {0x0,0xFF,0xF4,0x5F };
        #region CanNotDecrypt
        public static byte[] EncryptNotReverse(this byte[] bytes, PasswordEncrypt passwordEncrypt = PasswordEncrypt.Hash)
        {
            throw new Exception();
        }

        #endregion
        #region OneKey
        #region SobreCargaEncrypt
        public static byte[] Encrypt(this byte[] bytes, string password, DataEncrypt dataEncrypt=DataEncrypt.Cesar, LevelEncrypt level=LevelEncrypt.Normal, PasswordEncrypt passwordEncrypt=PasswordEncrypt.Nothing,Ordre order=Ordre.Consecutiu)
        {
            if (password == null) password = "";
            return Encrypt(bytes, Serializar.GetBytes(password), dataEncrypt, passwordEncrypt, level,order);
        }
        public static byte[] Encrypt(this byte[] bytes, byte[] password, DataEncrypt dataEncrypt = DataEncrypt.Cesar, LevelEncrypt level = LevelEncrypt.Normal, PasswordEncrypt passwordEncrypt = PasswordEncrypt.Nothing,Ordre order=Ordre.Consecutiu)
        {
            return Encrypt(bytes, password, dataEncrypt, passwordEncrypt, level,order);
        }
        internal static byte[] Encrypt(this byte[] bytes, byte[] password, DataEncrypt dataEncrypt, PasswordEncrypt passwordEncrypt, LevelEncrypt level,Ordre order=Ordre.Consecutiu)
        {
            if (password == null) password = new byte[0];
            return Encrypt(bytes, password.EncryptNotReverse(passwordEncrypt), dataEncrypt, passwordEncrypt, level,order);
        }
        #endregion
        internal static byte[] Encrypt(this byte[] bytes, byte[] password, DataEncrypt dataEncrypt, LevelEncrypt level,Ordre order)
        {
            byte[] bytesEncrypted=null;
            switch(dataEncrypt)
            {
                case DataEncrypt.Cesar: bytesEncrypted = EncryptCesar(bytes, password, level,order); break;
                case DataEncrypt.Disimulat: bytesEncrypted = EncryptDisimulat(bytes, password, level,order); break;
            }
            return bytesEncrypted;
        }
        #region SobreCargaDecrypt
        public static byte[] Decrypt(this byte[] bytes, string password, DataEncrypt dataEncrypt = DataEncrypt.Cesar, LevelEncrypt level = LevelEncrypt.Normal, PasswordEncrypt passwordEncrypt = PasswordEncrypt.Nothing,Ordre order=Ordre.Consecutiu)
        {
            if (password == null) password = "";
            return Decrypt(bytes, Serializar.GetBytes(password), dataEncrypt, passwordEncrypt, level,order);
        }
        public static byte[] Decrypt(this byte[] bytes, byte[] password, DataEncrypt dataEncrypt = DataEncrypt.Cesar, LevelEncrypt level = LevelEncrypt.Normal, PasswordEncrypt passwordEncrypt = PasswordEncrypt.Nothing,Ordre order=Ordre.Consecutiu)
        {
            if (password == null) password = new byte[0];
            return Decrypt(bytes, password, dataEncrypt, passwordEncrypt, level,order);
        }
        internal static byte[] Decrypt(this byte[] bytes, byte[] password, DataEncrypt dataEncrypt, PasswordEncrypt passwordEncrypt, LevelEncrypt level, Ordre order)
        {
            if (password == null) password = new byte[0];
            return Decrypt(bytes, password.EncryptNotReverse(passwordEncrypt), dataEncrypt, passwordEncrypt, level,order);
        }
        #endregion
        internal static byte[] Decrypt(this byte[] bytes, byte[] password, DataEncrypt dataDecrypt, LevelEncrypt level,Ordre order)
        {
            byte[] bytesDecrypted = null;
            switch (dataDecrypt)
            {
                case DataEncrypt.Cesar:bytesDecrypted = DecryptCesar(bytes, password, level,order); break;
                case DataEncrypt.Disimulat: bytesDecrypted = DecryptDisimulat(bytes, password, level,order); break;
            }
            return bytesDecrypted;
        }

        #region disimulat Encrypt
        private static byte[] EncryptDisimulat(byte[] bytes, byte[] password, LevelEncrypt level, Ordre order)
        {
            throw new NotImplementedException();
        }
        private static byte[] DecryptDisimulat(byte[] bytes, byte[] password, LevelEncrypt level, Ordre order)
        {
            throw new NotImplementedException();
        }
        #endregion
        #region Cesar encrypt
        private static byte[] EncryptCesar(byte[] bytes, byte[] password, LevelEncrypt level, Ordre order)
        {
            throw new NotImplementedException();
        }
        private static byte[] DecryptCesar(byte[] bytes, byte[] password, LevelEncrypt level, Ordre order)
        {
            throw new NotImplementedException();
        }
        #endregion
        #endregion
        //testing pendiente
        #region MultiKey
        #region Escollir clau per caracter
        //parte en comun :)
        private static byte[] EncryptDecryptCommun(MetodoMultiKey metodo, byte[] data, byte[][] passwords, byte[] bytesChange, DataEncrypt[] dataEncrypt, PasswordEncrypt[] passwordsEncrypt, LevelEncrypt level, Ordre order)
        {
            //por testear!!
            int numCanvis = 0;
            byte[] passwordActual;
            DataEncrypt dataEncryptAct;
            PasswordEncrypt passwordEncryptAct;
            byte[] bytesResult = new byte[0];
            byte[] byteResultAux;
            byte[][] dataSplited = data.Split(bytesChange);
            List<byte[]> dataResultSplited = new List<byte[]>();
            //opero
            passwordEncryptAct = passwordsEncrypt.DameElementoActual(order, numCanvis);
            dataEncryptAct = dataEncrypt.DameElementoActual(order, numCanvis);
            passwordActual = passwords.DameElementoActual(order, numCanvis);
            byteResultAux = metodo(dataSplited[0], passwordActual, dataEncryptAct, passwordEncryptAct, level,order);
            if (data.BuscarArray(bytesChange)>-1)//si tiene marca la pongo
             byteResultAux= byteResultAux.AddArray(bytesChange);
            dataResultSplited.Add(byteResultAux);
            numCanvis++;
            for (int i = 1; i < dataSplited.Length-1; i++)
            {
                
                    passwordEncryptAct = passwordsEncrypt.DameElementoActual(order, numCanvis);
                    dataEncryptAct = dataEncrypt.DameElementoActual(order, numCanvis);
                    passwordActual = passwords.DameElementoActual(order, numCanvis);
                    byteResultAux = metodo(dataSplited[i], passwordActual, dataEncryptAct, passwordEncryptAct, level,order).AddArray(bytesChange);
                    dataResultSplited.Add(byteResultAux);
                    numCanvis++;
                
            }
            if(dataSplited.Length>1)
            {
                if (dataSplited[dataSplited.Length - 1].Length != 0)//si no acaba en la marca es que hay bytes
                {
                    passwordEncryptAct = passwordsEncrypt.DameElementoActual(order, numCanvis);
                    dataEncryptAct = dataEncrypt.DameElementoActual(order, numCanvis);
                    passwordActual = passwords.DameElementoActual(order, numCanvis);
                    byteResultAux = metodo(dataSplited[dataSplited.Length - 1], passwordActual, dataEncryptAct, passwordEncryptAct, level,order).AddArray(bytesChange);
                    dataResultSplited.Add(byteResultAux);
      
                }
                else dataResultSplited.Add(bytesChange);//añado la marca a los bytes finales
            }

            return bytesResult.AddArray(dataResultSplited.ToArray());
        }

        #region SobreCargaEncrypt
        public static byte[] Encrypt(this byte[] bytes, string[] passwords, DataEncrypt dataEncrypt =DataEncrypt.Cesar, PasswordEncrypt passwordEncrypt = PasswordEncrypt.Hash, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu)
        {
            return Encrypt(bytes, passwords, BytesChangeDefault, new DataEncrypt[] { dataEncrypt }, new PasswordEncrypt[] { passwordEncrypt }, level, escogerKey);
        }
        public static byte[] Encrypt(this byte[] bytes, string[] passwords, DataEncrypt[] dataEncrypt, PasswordEncrypt passwordEncrypt = PasswordEncrypt.Hash, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu)
        {
            return Encrypt(bytes, passwords, BytesChangeDefault, dataEncrypt, new PasswordEncrypt[] { passwordEncrypt }, level, escogerKey);
        }
        public static byte[] Encrypt(this byte[] bytes, string[] passwords, PasswordEncrypt[] passwordEncrypt, DataEncrypt dataEncrypt = DataEncrypt.Cesar, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu)
        {
            return Encrypt(bytes, passwords, BytesChangeDefault, new DataEncrypt[] { dataEncrypt }, passwordEncrypt, level, escogerKey);
        }
        public static byte[] Encrypt(this byte[] bytes, string[] passwords, DataEncrypt[] dataEncrypt, PasswordEncrypt[] passwordEncrypt, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu)
        {
            return Encrypt(bytes, passwords, BytesChangeDefault, dataEncrypt, passwordEncrypt, level, escogerKey);
        }

        public static byte[] Encrypt(this byte[] bytes, byte[][] passwords, DataEncrypt dataEncrypt = DataEncrypt.Cesar, PasswordEncrypt passwordEncrypt = PasswordEncrypt.Hash, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu)
        {
            return Encrypt(bytes, passwords, BytesChangeDefault, new DataEncrypt[] { dataEncrypt }, new PasswordEncrypt[] { passwordEncrypt }, level, escogerKey);
        }
        public static byte[] Encrypt(this byte[] bytes, byte[][] passwords, DataEncrypt[] dataEncrypt, PasswordEncrypt passwordEncrypt = PasswordEncrypt.Hash, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu)
        {
            return Encrypt(bytes, passwords, BytesChangeDefault, dataEncrypt, new PasswordEncrypt[] { passwordEncrypt }, level, escogerKey);
        }
        public static byte[] Encrypt(this byte[] bytes, byte[][] passwords, PasswordEncrypt[] passwordEncrypt, DataEncrypt dataEncrypt = DataEncrypt.Cesar, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu)
        {
            return Encrypt(bytes, passwords, BytesChangeDefault, new DataEncrypt[] { dataEncrypt }, passwordEncrypt, level, escogerKey);
        }

        public static byte[] Encrypt(this byte[] bytes, byte[][] passwords, DataEncrypt[] dataEncrypt, PasswordEncrypt[] passwordEncrypt, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu)
        {
            return Encrypt(bytes, passwords, BytesChangeDefault,  dataEncrypt , passwordEncrypt, level, escogerKey);
        }
        public static byte[] Encrypt(this byte[] bytes, string[] passwords, byte[] bytesChange, DataEncrypt dataEncrypt = DataEncrypt.Cesar, PasswordEncrypt passwordEncrypt = PasswordEncrypt.Hash, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu)
        {
            return Encrypt(bytes, passwords, bytesChange, new DataEncrypt[] { dataEncrypt }, new PasswordEncrypt[] { passwordEncrypt }, level, escogerKey);
        }
        public static byte[] Encrypt(this byte[] bytes, string[] passwords, byte[] bytesChange, DataEncrypt[] dataEncrypt, PasswordEncrypt passwordEncrypt = PasswordEncrypt.Hash, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu)
        {
            return Encrypt(bytes, passwords, bytesChange, dataEncrypt, new PasswordEncrypt[] { passwordEncrypt }, level, escogerKey);
        }
        public static byte[] Encrypt(this byte[] bytes, string[] passwords, byte[] bytesChange, PasswordEncrypt[] passwordEncrypt, DataEncrypt dataEncrypt = DataEncrypt.Cesar, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu)
        {
            return Encrypt(bytes, passwords, bytesChange, new DataEncrypt[] { dataEncrypt }, passwordEncrypt, level, escogerKey);
        }
        public static byte[] Encrypt(this byte[] bytes, string[] passwords, byte[] bytesChange, DataEncrypt[] dataEncrypt, PasswordEncrypt[] passwordEncrypt, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu)
        {
            return Encrypt(bytes, passwords, bytesChange, dataEncrypt, passwordEncrypt, level, escogerKey);
        }

        public static byte[] Encrypt(this byte[] bytes, byte[][] passwords, byte[] bytesChange, DataEncrypt dataEncrypt = DataEncrypt.Cesar, PasswordEncrypt passwordEncrypt = PasswordEncrypt.Hash, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu)
        {
            return Encrypt(bytes, passwords, bytesChange, new DataEncrypt[] { dataEncrypt }, new PasswordEncrypt[] { passwordEncrypt }, level, escogerKey);
        }
        public static byte[] Encrypt(this byte[] bytes, byte[][] passwords, byte[] bytesChange, DataEncrypt[] dataEncrypt, PasswordEncrypt passwordEncrypt = PasswordEncrypt.Hash, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu)
        {
            return Encrypt(bytes, passwords, bytesChange, dataEncrypt, new PasswordEncrypt[] { passwordEncrypt }, level, escogerKey);
        }
        public static byte[] Encrypt(this byte[] bytes, byte[][] passwords, byte[] bytesChange, PasswordEncrypt[] passwordEncrypt, DataEncrypt dataEncrypt = DataEncrypt.Cesar, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu)
        {
            return Encrypt(bytes, passwords, bytesChange, new DataEncrypt[] { dataEncrypt }, passwordEncrypt, level, escogerKey);
        }
        #endregion
        public static byte[] Encrypt(this byte[] bytes, byte[][] passwords, byte[] bytesChange, DataEncrypt[] dataEncrypt, PasswordEncrypt[] passwordEncrypt, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu)
        {
            return EncryptDecryptCommun(Encrypt, bytes, passwords, bytesChange, dataEncrypt, passwordEncrypt, level, escogerKey);
        }
        #region SobreCargaDecrypt
        public static byte[] Decrypt(this byte[] bytes, string[] passwords, DataEncrypt dataEncrypt = DataEncrypt.Cesar, PasswordEncrypt passwordEncrypt = PasswordEncrypt.Hash, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu)
        {
            return Decrypt(bytes, passwords, new DataEncrypt[] { dataEncrypt }, new PasswordEncrypt[] { passwordEncrypt }, level, escogerKey);
        }
        public static byte[] Decrypt(this byte[] bytes, string[] passwords, DataEncrypt[] dataEncrypt, PasswordEncrypt passwordEncrypt = PasswordEncrypt.Hash, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu)
        {
            return Decrypt(bytes, passwords,  dataEncrypt, new PasswordEncrypt[] { passwordEncrypt }, level, escogerKey);
        }
        public static byte[] Decrypt(this byte[] bytes, string[] passwords, PasswordEncrypt[] passwordEncrypt, DataEncrypt dataEncrypt = DataEncrypt.Cesar, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu)
        {
            return Decrypt(bytes, passwords,  new DataEncrypt[] { dataEncrypt }, passwordEncrypt, level, escogerKey);
        }
        public static byte[] Decrypt(this byte[] bytes, string[] passwords, DataEncrypt[] dataEncrypt, PasswordEncrypt[] passwordEncrypt, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu)
        {
            return Decrypt(bytes, passwords,BytesChangeDefault, dataEncrypt, passwordEncrypt, level, escogerKey);
        }
        public static byte[] Decrypt(this byte[] bytes, byte[][] passwords, DataEncrypt dataEncrypt = DataEncrypt.Cesar, PasswordEncrypt passwordEncrypt = PasswordEncrypt.Hash, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu)
        {
            return Decrypt(bytes, passwords,  new DataEncrypt[] { dataEncrypt }, new PasswordEncrypt[] { passwordEncrypt }, level, escogerKey);
        }
        public static byte[] Decrypt(this byte[] bytes, byte[][] passwords, DataEncrypt[] dataEncrypt, PasswordEncrypt passwordEncrypt = PasswordEncrypt.Hash, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu)
        {
            return Decrypt(bytes, passwords,  dataEncrypt, new PasswordEncrypt[] { passwordEncrypt }, level, escogerKey);
        }
        public static byte[] Decrypt(this byte[] bytes, byte[][] passwords, PasswordEncrypt[] passwordEncrypt, DataEncrypt dataEncrypt = DataEncrypt.Cesar, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu)
        {
            return Decrypt(bytes, passwords,  new DataEncrypt[] { dataEncrypt }, passwordEncrypt, level, escogerKey);
        }

        public static byte[] Decrypt(this byte[] bytes, byte[][] passwords, DataEncrypt[] dataEncrypt, PasswordEncrypt[] passwordEncrypt, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu)
        {
            return Decrypt(bytes, passwords, BytesChangeDefault, dataEncrypt, passwordEncrypt, level, escogerKey);
        }
        public static byte[] Decrypt(this byte[] bytes, string[] passwords, byte[] bytesChange, DataEncrypt dataEncrypt = DataEncrypt.Cesar, PasswordEncrypt passwordEncrypt = PasswordEncrypt.Hash, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu)
        {
            return Decrypt(bytes, passwords,bytesChange, new DataEncrypt[] { dataEncrypt }, new PasswordEncrypt[] { passwordEncrypt }, level, escogerKey);
        }
        public static byte[] Decrypt(this byte[] bytes, string[] passwords, byte[] bytesChange, DataEncrypt[] dataEncrypt, PasswordEncrypt passwordEncrypt = PasswordEncrypt.Hash, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu)
        {
            return Decrypt(bytes, passwords,bytesChange, dataEncrypt, new PasswordEncrypt[] { passwordEncrypt }, level, escogerKey);
        }
        public static byte[] Decrypt(this byte[] bytes, string[] passwords, byte[] bytesChange, PasswordEncrypt[] passwordEncrypt, DataEncrypt dataEncrypt = DataEncrypt.Cesar, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu)
        {
            return Decrypt(bytes, passwords, bytesChange, new DataEncrypt[] { dataEncrypt }, passwordEncrypt, level, escogerKey);
        }
        public static byte[] Decrypt(this byte[] bytes, string[] passwords, byte[] bytesChange, DataEncrypt[] dataEncrypt, PasswordEncrypt[] passwordEncrypt, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu)
        {
            if (passwords == null || dataEncrypt == null || passwordEncrypt == null) throw new ArgumentNullException();
            List<byte[]> passwordBytes = new List<byte[]>();
            for (int i = 0; i < passwords.Length; i++)
                passwordBytes.Add(Serializar.GetBytes(passwords[i]));
            return Decrypt(bytes, passwordBytes.ToArray(), bytesChange, dataEncrypt, passwordEncrypt, level, escogerKey);
        }
        public static byte[] Decrypt(this byte[] bytes, byte[][] passwords, byte[] bytesChange, DataEncrypt dataEncrypt = DataEncrypt.Cesar, PasswordEncrypt passwordEncrypt = PasswordEncrypt.Hash, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu)
        {
            return Decrypt(bytes, passwords, bytesChange, new DataEncrypt[] { dataEncrypt }, new PasswordEncrypt[] { passwordEncrypt }, level, escogerKey);
        }
        public static byte[] Decrypt(this byte[] bytes, byte[][] passwords, byte[] bytesChange, DataEncrypt[] dataEncrypt, PasswordEncrypt passwordEncrypt = PasswordEncrypt.Hash, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu)
        {
            return Decrypt(bytes, passwords, bytesChange, dataEncrypt, new PasswordEncrypt[] { passwordEncrypt }, level, escogerKey);
        }
        public static byte[] Decrypt(this byte[] bytes, byte[][] passwords, byte[] bytesChange, PasswordEncrypt[] passwordEncrypt, DataEncrypt dataEncrypt = DataEncrypt.Cesar, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu)
        {
            return Decrypt(bytes, passwords, bytesChange, new DataEncrypt[] { dataEncrypt }, passwordEncrypt, level, escogerKey);
        }
        #endregion
        public static byte[] Decrypt(this byte[] bytes, byte[][] passwords, byte[] bytesChange, DataEncrypt[] dataEncrypt, PasswordEncrypt[] passwordEncrypt, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu)
        {
            return EncryptDecryptCommun(Decrypt, bytes, passwords, bytesChange, dataEncrypt, passwordEncrypt, level, escogerKey);
        }

        #endregion
        #endregion
    }
}
