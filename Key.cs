using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Xml;
using Gabriel.Cat.Extension;
using System.IO;


namespace Gabriel.Cat.Seguretat
{
    public class Key
    {
       
        public class ItemKey
        {

            public int MethodData { get; set; }
            public int MethodPassword { get; set; }
            public byte[] Password { get; set; }
            
            public ItemKey(int methodData = 0, int methodPassword = 0, bool randomKey = true, int lenghtRandomKey = 15):this(randomKey?MiRandom.NextBytes(lengthRandomKey):null,methodData,methodPassword){}
      public ItemKey(string password,int methodData = 0, int methodPassword = 0):this(Serializar.GetBytes(password),methodData,methodPassword)
      {}      
            
            public ItemKey(byte[] password,int methodData = 0, int methodPassword = 0){
                MethodData = methodData;
                MethodPassword = methodPassword;
                Password=password;
            }
            public ItemKey(XmlNode nodeItem)
            {
                MethodData = Convert.ToInt32(nodeItem.ChildNodes[0].InnerText);
                MethodPassword = Convert.ToInt32(nodeItem.ChildNodes[1].InnerText);
                Password = (byte[])(Hex)nodeItem.ChildNodes[2].InnerText;
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
                nodeString.Append((string)(Hex)Password);
                nodeString.Append("</Password>");
                nodeString.Append("</ItemKey>");
                return nodeString;
            }
            public static XmlDocument ToXml(IList<ItemKey> itemsKey)
            {
                if (Equals(itemsKey,default))
                    throw new ArgumentNullException("itemsKey");
                    
                XmlDocument xmlKey = new XmlDocument();
                StringBuilder strKey = new StringBuilder();
                strKey.Append("<Key>");
                for(int i=0;i<itemsKey.Count;i++)
                    strKey.Append(itemsKey[i].IToXmlNode());
                strKey.Append("</Key>");
                xmlKey.LoadXml(strKey.ToString());
                xmlKey.Normalize();
                return xmlKey;
            }
            public static ItemKey[] ToItemKeyArray(XmlDocument xmlKey)
            {
                if (Equals(xmlKey,default))
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
            public delegate byte[] MethodEncryptReversible(byte[] data, byte[] password, bool encrypt = true);


            public MethodEncryptReversible MethodData { get; set; }

            public ItemEncryptationData(MethodEncryptReversible methodData)
            {
                MethodData = methodData;

            }
            public byte[] Encrypt(byte[] data, byte[] key)
            {
                return MethodData(data, key);
            }
            public byte[] Decrypt(byte[] data, byte[] key)
            {
                return MethodData(data, key, false);
            }
        }
        public class ItemEncryptationPassword
        {
            public delegate string MethodEncryptNonReversible(byte[] password);
            public MethodEncryptNonReversible MethodPassword { get; set; }

            public ItemEncryptationPassword(MethodEncryptNonReversible methodPassword)
            {
                MethodPassword = methodPassword;

            }
            public string Encrypt(byte[] key)
            {
                return MethodPassword(key);
            }
        }
      
        List<ItemEncryptationData> itemsEncryptData;
        List<ItemEncryptationPassword> itemsEncryptPassword;
        List<ItemKey> itemsKey;
        
        public Key(bool initDefaultMethods=true)
        {
            itemsKey = new List<ItemKey>();
            itemsEncryptData = new List<ItemEncryptationData>();
            itemsEncryptPassword = new List<ItemEncryptationPassword>();
            if(initDefaultMethods)
            	Init();
        }
        public Key(IEnumerable<ItemKey> itemsKey,bool initDefaultMethods=true)
            : this(initDefaultMethods)
        {
            ItemsKey.AddRange(itemsKey);
        }
        public Key(XmlDocument xmlKey,bool initDefaultMethods=true)
            : this(initDefaultMethods)
        {
            itemsKey.AddRange(ItemKey.ToItemKeyArray(xmlKey));
        }
	public Key(byte[] keyFileXmlEncrypted,bool initDefaultMethods,params Key[] keys):this(initDefaultMethods){
	XmlDocument xmlKey;
	byte[] keyData=keyFileXmlEncrypted;
		for(int i=keys.Length-1;i>=0;i--)
		   keyData=keys[i].Decrypt(keyData);
	xmlKey=new XmlDocument();
	xmlKey.Load(Serializar.ToString(keyData));
	itemsKey.AddRange(ItemKey.ToItemKeyArray(xmlKey));	
		   
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
        private void Init(){
            ItemsEncryptData.Add(new ItemEncryptationData(MetodoCesar));
            ItemsEncryptData.Add(new ItemEncryptationData(MetodoPerdut));
            ItemsEncryptPassword.Add(new ItemEncryptationPassword(MetodoHash));
            
        }
        public byte[] Encrypt(byte[] data)
        {
            ItemEncryptationData itemEncryptData;
            ItemEncryptationPassword itemEncryptPassword=null;
            for (int i = 0, f = itemsKey.Count; i < f; i++)
            {
                itemEncryptData = itemsEncryptData[itemsKey[i].MethodData];
                if (itemsEncryptPassword.Count > 0)
                    itemEncryptPassword = itemsEncryptPassword[itemsKey[i].MethodPassword];

                data = itemEncryptData.Encrypt(data, itemEncryptPassword.Encrypt(itemsKey[i].Password) ?? itemsKey[i].Password);
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
            ItemEncryptationPassword itemEncryptPassword=null;
            for (int i = itemsKey.Count - 1; i >= 0; i--)
            {

                itemEncryptData = itemsEncryptData[itemsKey[i].MethodData];
                if(itemsEncryptPassword.Count>0)
                itemEncryptPassword = itemsEncryptPassword[itemsKey[i].MethodPassword];
            
                data = itemEncryptData.Decrypt(data, itemEncryptPassword.Encrypt(itemsKey[i].Password) ?? itemsKey[i].Password);
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

        public byte[] GetBytes(params Key[] keysToEncryptData)
        {
           XmlDocument xmlKey=ItemKey.ToXml(this.ItemsKey);
           byte[] data=Serializar.GetBytes(xmlKey.OuterXml);
           for(int i=0;i<keysToEncryptData.Length;i++)
           	data=keysToEncryptData.Encrypt(data);
           return data;	
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
            if (Equals(passwords, default))
                throw new ArgumentNullException();
            
               
            Key key = new Key();

            for (int i = 0; i < passwords.Count; i++)
            {
                if (!String.IsNullOrEmpty(passwords[i]))
                key.ItemsKey.Add(new ItemKey() { Password =Serializar.GetBytes(passwords[i]), MethodData=CESAR});
            }
            if (passwords.Count != 0)
            {
                key.ItemsKey[0].MethodData =PERDUT;
                key.ItemsKey[key.ItemsKey.Count - 1].MethodData = PERDUT;
            }
            return key;
        }

        private static byte[] MetodoPerdut(byte[] data, byte[] password, bool encrypt)
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

        private static byte[] MetodoCesar(byte[] data, byte[] password, bool encrypt)
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

        private static string MetodoHash(byte[] password)
        {
            return password.EncryptNotReverse();
        }
    }
}
