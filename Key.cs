using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Xml;
using Gabriel.Cat.Extension;
using System.IO;
using Gabriel.Cat.Binaris;

namespace Gabriel.Cat.Seguretat
{
    public class Key
    {
        public class ItemKeyBinary : ElementoBinario
        {
            static Formato itemKeyFormat;
            static ItemKeyBinary()
            {
                //inicializo la parte del formato aqui
                itemKeyFormat = new Formato();
                itemKeyFormat.ElementosArchivo.Add(Binaris.ElementoBinario.ElementosTipoAceptado(Serializar.TiposAceptados.Int));
                itemKeyFormat.ElementosArchivo.Add(Binaris.ElementoBinario.ElementosTipoAceptado(Serializar.TiposAceptados.Int));
                itemKeyFormat.ElementosArchivo.Add(Binaris.ElementoBinario.ElementosTipoAceptado(Serializar.TiposAceptados.String));
            }

            public override byte[] GetBytes(object obj)
            {
                return GetBytes(obj as ItemKey);
            }

            public ItemKey GetItemKey(byte[] bytes)
            {
                return GetItemKey(new MemoryStream(bytes));
            }

            public override object GetObject(MemoryStream bytes)
            {
                return GetItemKey(bytes);
            }
            public static byte[] GetBytes(ItemKey itemKey)
            {
                if (itemKey == null) throw new ArgumentNullException();
                return itemKeyFormat.GetBytes(new object[] { itemKey.MethodData, itemKey.MethodPassword, itemKey.Password });
            }


            public static ItemKey GetItemKey(MemoryStream strBytes)
            {
                if (strBytes == null || !strBytes.CanRead) throw new ArgumentException();
                object[] parts = itemKeyFormat.GetPartsOfObject(strBytes);
                return new ItemKey() { MethodData = (int)parts[0], MethodPassword = (int)parts[1], Password = (string)parts[2] };
            }

        }
        public class ItemKey
        {


            public int MethodData { get; set; }
            public int MethodPassword { get; set; }
            public string Password { get; set; }
            public ItemKey(int methodData = 0, int methodPassword = 0, bool randomKey = true, int lenghtRandomKey = 15)
            {
                MethodData = methodData;
                MethodPassword = methodPassword;
                if (!randomKey)
                    Password = "";
                else
                    GenerateRandomKey(lenghtRandomKey);
            }
            public ItemKey(XmlNode nodeItem)
            {
                MethodData = Convert.ToInt32(nodeItem.ChildNodes[0].InnerText);
                MethodPassword = Convert.ToInt32(nodeItem.ChildNodes[1].InnerText);
                Password = Serializar.ToString((Hex)nodeItem.ChildNodes[2].InnerText);
            }
            public ItemKey(MemoryStream strItems)
            {
                ItemKey item = ItemKeyBinary.GetItemKey(strItems);
                MethodData = item.MethodData;
                MethodPassword = item.MethodPassword;
                Password = item.Password;
            }
            public ItemKey(byte[] bytesItem)
                : this(new MemoryStream(bytesItem))
            {
            }
            public void GenerateRandomKey(int lenght = 15)
            {
                if (lenght < 0)
                    throw new ArgumentOutOfRangeException();
                StringBuilder str = new StringBuilder();
                for (int i = 0; i < lenght; i++)
                    str.Append((char)MiRandom.Next(256));

                Password = str.ToString();
            }

            #region XmlSerialitzacion
            public XmlNode ToXmlNode()
            {
                XmlDocument node = new XmlDocument();
                node.LoadXml(IToXmlNode().ToString());
                node.Normalize();
                return node.FirstChild;
            }
            private StringBuilder IToXmlNode()
            {
                StringBuilder nodeString = new StringBuilder();
                nodeString.Append("<ItemKey>");
                nodeString.Append("<MethodData>");
                nodeString.Append(MethodData);
                nodeString.Append("</MethodData>");
                nodeString.Append("<MethodPassword>");
                nodeString.Append(MethodPassword);
                nodeString.Append("</MethodPassword>");
                nodeString.Append("<Password>");
                nodeString.Append((string)(Hex)Serializar.GetBytes(Password));
                nodeString.Append("</Password>");
                nodeString.Append("</ItemKey>");
                return nodeString;
            }
            public static XmlDocument ToXml(IEnumerable<ItemKey> itemsKey)
            {
                if (itemsKey == null)
                    throw new ArgumentNullException("itemsKey");
                XmlDocument xmlKey = new XmlDocument();
                StringBuilder strKey = new StringBuilder();
                strKey.Append("<Key>");
                foreach (ItemKey item in itemsKey)
                    strKey.Append(item.IToXmlNode());
                strKey.Append("</Key>");
                xmlKey.LoadXml(strKey.ToString());
                xmlKey.Normalize();
                return xmlKey;
            }
            public static ItemKey[] ToItemKeyArray(XmlDocument xmlKey)
            {
                if (xmlKey == null)
                    throw new ArgumentNullException("xmlKey");
                ItemKey[] itemsKey = new ItemKey[xmlKey.FirstChild.ChildNodes.Count];
                for (int i = 0, f = xmlKey.FirstChild.ChildNodes.Count; i < f; i++)
                    itemsKey[i] = new ItemKey(xmlKey.FirstChild.ChildNodes[i]);
                return itemsKey;
            }
            #endregion

        }
        public class ItemEncryptationData
        {
            public delegate byte[] MethodEncryptReversible(byte[] data, string password, bool encrypt = true);


            public MethodEncryptReversible MethodData { get; set; }

            public ItemEncryptationData(MethodEncryptReversible methodData)
            {
                MethodData = methodData;

            }
            public byte[] Encrypt(byte[] data, string key)
            {
                return MethodData(data, key);
            }
            public byte[] Decrypt(byte[] data, string key)
            {
                return MethodData(data, key, false);
            }
        }
        public class ItemEncryptationPassword
        {
            public delegate string MethodEncryptNonReversible(string password);
            public MethodEncryptNonReversible MethodPassword { get; set; }

            public ItemEncryptationPassword(MethodEncryptNonReversible methodPassword)
            {
                MethodPassword = methodPassword;

            }
            public string Encrypt(string key)
            {
                return MethodPassword(key);
            }
        }
        public class KeyBinary : ElementoBinario
        {
            static Formato keyFormat;
            static KeyBinary()
            {
                keyFormat = new Formato();
                keyFormat.ElementosArchivo.Add(new ElementoIEnumerableBinario(new ItemKeyBinary(), ElementoIEnumerableBinario.LongitudBinaria.Long));
            }
            public static byte[] GetBytes(Key key)
            {
                if (key == null) throw new ArgumentNullException();
                return keyFormat.GetBytes(new Object[] { key.ItemsKey });
            }
            public static Key GetKey(MemoryStream strObj)
            {
                if (strObj == null || !strObj.CanRead) throw new ArgumentException();
                Object[] parts = keyFormat.GetPartsOfObject(strObj)[0] as Object[];
                return new Key(parts.Casting<ItemKey>());
            }
            public static Key GetKey(byte[] bytesObj)
            {
                return GetKey(new MemoryStream(bytesObj));
            }

            public override byte[] GetBytes(object obj)
            {
                return GetBytes(obj as Key);
            }

            public override object GetObject(MemoryStream bytes)
            {
                return GetKey(bytes);
            }
        }

        List<ItemEncryptationData> itemsEncryptData;
        List<ItemEncryptationPassword> itemsEncryptPassword;
        List<ItemKey> itemsKey;
        public Key()
        {
            itemsKey = new List<ItemKey>();
            itemsEncryptData = new List<ItemEncryptationData>();
            itemsEncryptPassword = new List<ItemEncryptationPassword>();
        }
        public Key(IEnumerable<ItemKey> itemsKey)
            : this()
        {
            ItemsKey.AddRange(itemsKey);
        }
        public Key(XmlDocument xmlKey)
            : this()
        {
            itemsKey.AddRange(ItemKey.ToItemKeyArray(xmlKey));
        }
        public Key(string fileKey, params string[] keysToDecrypt) : this(fileKey,true,keysToDecrypt)
        {

        }
        public Key(string fileKey, bool setDefaultMethodsEncrypt, params string[] keysToDecrypt) : this(fileKey, GetKey(keysToDecrypt), setDefaultMethodsEncrypt)
        {

        }
        public Key(FileInfo fileKey, params string[] keysToDecrypt) : this(fileKey, GetKey(keysToDecrypt), true)
        {
        }
        public Key(FileInfo fileKey, bool setDefaultMethodsEncrypt, params string[] keysToDecrypt) : this(fileKey, GetKey(keysToDecrypt), setDefaultMethodsEncrypt)
        {
        }

        public Key(string fileKey, Key keyToDecrypt = null, bool setDefaultMethodsEncrypt = true) : this(new FileInfo(fileKey), keyToDecrypt, setDefaultMethodsEncrypt)
        { }
        public Key(FileInfo fileKey, Key keyToDecrypt = null, bool setDefaultMethodsEncrypt = true)
            : this(new MemoryStream(fileKey.GetStream().GetAllBytes()), keyToDecrypt, setDefaultMethodsEncrypt)
        {
        }
        public Key(MemoryStream strOneKey, Key keyToDecrypt = null, bool setDefaultMethodsEncrypt = true)
            : this()
        {
            MemoryStream strDecrypted;
            Key key;
            try
            {
                if (keyToDecrypt != null)
                {
                    strDecrypted = new MemoryStream(keyToDecrypt.Decrypt(strOneKey.GetAllBytes()));
                    strDecrypted.Position = strOneKey.Position;
                }
                else
                    strDecrypted = strOneKey;
                key = KeyBinary.GetKey(strDecrypted);
                itemsKey = key.itemsKey;
                if (setDefaultMethodsEncrypt)
                {
                    itemsEncryptData.Add(new ItemEncryptationData(MetodoCesar));
                    itemsEncryptData.Add(new ItemEncryptationData(MetodoPerdut));
                    itemsEncryptPassword.Add(new ItemEncryptationPassword(MetodoHash));
                }
                strOneKey.Position = strDecrypted.Position;
            }
            catch (Exception m)
            {
                throw new Exception("La llave para descifrar los datos de la llave a cargar no es la correcta!", m);
            }
        }
        public Key(byte[] bytesKey, Key keyToDecrypt = null)
            : this(new MemoryStream(bytesKey), keyToDecrypt)
        {
        }
        public List<ItemKey> ItemsKey
        {
            get { return itemsKey; }
        }

        public List<ItemEncryptationData> ItemsEncryptData
        {
            get
            {
                return itemsEncryptData;
            }
        }
        public List<ItemEncryptationPassword> ItemsEncryptPassword
        {
            get
            {
                return itemsEncryptPassword;
            }
        }
        public byte[] Encrypt(byte[] data)
        {
            ItemEncryptationData itemEncryptData;
            ItemEncryptationPassword itemEncryptPassword;
            for (int i = 0, f = itemsKey.Count; i < f; i++)
            {
                itemEncryptData = itemsEncryptData[itemsKey[i].MethodData];
                itemEncryptPassword = itemsEncryptPassword[itemsKey[i].MethodPassword];
                data = itemEncryptData.Encrypt(data, itemEncryptPassword.Encrypt(itemsKey[i].Password));
            }
            return data;
        }
        public string Encrypt(string data)
        {
            return Serializar.ToString(Encrypt(Serializar.GetBytes(data)));
        }
        public byte[] Decrypt(byte[] data)
        {
            ItemEncryptationData itemEncryptData;
            ItemEncryptationPassword itemEncryptPassword;
            for (int i = itemsKey.Count - 1; i >= 0; i--)
            {

                itemEncryptData = itemsEncryptData[itemsKey[i].MethodData];
                itemEncryptPassword = itemsEncryptPassword[itemsKey[i].MethodPassword];
                data = itemEncryptData.Decrypt(data, itemEncryptPassword.Encrypt(itemsKey[i].Password));
            }
            return data;
        }
        public string Decrypt(string data)
        {
            return Serializar.ToString(Decrypt(Serializar.GetBytes(data)));
        }
        public XmlDocument ToXml()
        {
            return ItemKey.ToXml(itemsKey);
        }

        public byte[] GetBytes(params string[] keysToEncryptData)
        {
            return GetBytes(GetKey(keysToEncryptData));
        }
        public byte[] GetBytes(Key keyToEncryptData = null)
        {
            byte[] bytes = KeyBinary.GetBytes(this);
            if (keyToEncryptData != null)
                bytes = keyToEncryptData.Encrypt(bytes);
            return bytes;
        }
        public static Key GetKey(long numeroDeRandomPasswords)
        {
            string[] randomPasswords = new string[numeroDeRandomPasswords];
            for (long i = 0; i < numeroDeRandomPasswords; i++)
            {
                randomPasswords[i] = (MiRandom.Next() + "").EncryptNotReverse(PasswordEncrypt.Sha256);
            }
            return GetKey(randomPasswords);

        }
        public static Key GetKey(params string[] passwords)
        {
            return GetKey((IList<string>)passwords);
        }
        public static Key GetKey(IList<string> passwords)
        {
            const int CESAR = 0, PERDUT = 1;
            if (passwords == null)
                throw new ArgumentNullException();
            
               
            Key key = new Key();
            key.ItemsEncryptData.Add(new ItemEncryptationData(MetodoCesar));
            key.ItemsEncryptData.Add(new ItemEncryptationData(MetodoPerdut));
            key.ItemsEncryptPassword.Add(new ItemEncryptationPassword(MetodoHash));
            for (int i = 0; i < passwords.Count; i++)
            {
                if (!String.IsNullOrEmpty(passwords[i]))
                key.ItemsKey.Add(new ItemKey() { Password = passwords[i], MethodData=CESAR});
            }
            if (passwords.Count != 0)
            {
                key.ItemsKey[0].MethodData =PERDUT;
                key.ItemsKey[key.ItemsKey.Count - 1].MethodData = PERDUT;
            }
            return key;
        }

        private static byte[] MetodoPerdut(byte[] data, string password, bool encrypt)
        {
            byte[] dataOut;
            if (encrypt)
            {
                dataOut = data.Encrypt(password, DataEncrypt.Perdut, LevelEncrypt.Highest);
            }
            else
            {
                dataOut = data.Decrypt(password, DataEncrypt.Perdut, LevelEncrypt.Highest);
            }
            return dataOut;
        }

        private static byte[] MetodoCesar(byte[] data, string password, bool encrypt)
        {
            byte[] dataOut;
            if (encrypt)
            {
                dataOut = data.Encrypt(password, DataEncrypt.Cesar, LevelEncrypt.Highest);
            }
            else
            {
                dataOut = data.Decrypt(password, DataEncrypt.Cesar, LevelEncrypt.Highest);
            }
            return dataOut;
        }

        private static string MetodoHash(string password)
        {
            return password.EncryptNotReverse();
        }
    }
}
