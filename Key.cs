using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Xml;
using Gabriel.Cat.Extension;
namespace Gabriel.Cat.Seguretat
{
    public class Key
    {
        public class ItemKey
        {
         
            public int MethodData { get; set; }
            public int MethodPassword { get; set; }
            public string Password { get; set; }

            public ItemKey(int methodData=0,int methodPassword=0,bool randomKey=true,int lenghtRandomKey=15)
            {
                MethodData = methodData;
                MethodPassword = methodPassword;
                if (!randomKey)
                    Password = "";
                else GenerateRandomKey(lenghtRandomKey);
            }

        

            public ItemKey(XmlNode nodeItem)
            {
                MethodData = Convert.ToInt32(nodeItem.ChildNodes[0].InnerText);
                MethodPassword = Convert.ToInt32(nodeItem.ChildNodes[1].InnerText);
                Password = Serializar.ToString(nodeItem.ChildNodes[2].InnerText.HexStringToByteArray());
            }

            public void GenerateRandomKey(int lenght=15)
            {
                if (lenght < 0)
                    throw new ArgumentOutOfRangeException();
                StringBuilder str = new StringBuilder();
                for (int i = 0; i < lenght; i++)
                    str.Append((char)MiRandom.Next(256));

                Password = str.ToString();
            }
            public XmlNode ToXmlNode()
            {
                StringBuilder nodeString = new StringBuilder();
                XmlDocument node = new XmlDocument();
                nodeString.Append("<ItemKey>");
                nodeString.Append("<MethodData>");
                nodeString.Append(MethodData);
                nodeString.Append("</MethodData>");
                nodeString.Append("<MethodPassword>");
                nodeString.Append(MethodPassword);
                nodeString.Append("</MethodPassword>");
                nodeString.Append("<Password>");
                nodeString.Append(Serializar.GetBytes(Password).ToHex());
                nodeString.Append("</Password>");
                nodeString.Append("</ItemKey>");
                node.LoadXml(nodeString.ToString());
                node.Normalize();
                return node.FirstChild;
            }

            public static XmlDocument ToXml(IEnumerable<ItemKey> itemsKey)
            {
                if (itemsKey == null)
                    throw new ArgumentNullException("itemsKey");
                XmlDocument xmlKey = new XmlDocument();
                StringBuilder strKey = new StringBuilder();
                strKey.Append("<Key>");
                foreach (ItemKey item in itemsKey)
                    strKey.Append(item.ToXmlNode().OuterXml);
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
        }
        public class ItemEncryptationData
        {
            public delegate string MethodEncryptReversible(string data, string password,bool encrypt=true);
            

            public MethodEncryptReversible MethodData { get; set; }

            public ItemEncryptationData(MethodEncryptReversible methodData)
            {
                MethodData = methodData;

            }
            public string Encrypt(string data,string key)
            {
                return MethodData(data,key);
            }
            public string Decrypt(string data, string key)
            {
                return MethodData(data, key,false);
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
        List<ItemEncryptationData> itemsEncryptData;
        List<ItemEncryptationPassword> itemsEncryptPassword;
        List<ItemKey> itemsKey;
        public Key()
        {
            itemsKey = new List<ItemKey>();
            itemsEncryptData = new List<ItemEncryptationData>();
            itemsEncryptPassword = new List<ItemEncryptationPassword>();
        }
        public Key(XmlDocument xmlKey):this()
        {
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
        public byte[] Encrypt(byte[] data)
        {
            return Encrypt(data.ToHex()).HexStringToByteArray();
        }
        public string Encrypt(string data)
        {
            for (int i = 0, f = itemsKey.Count; i < f; i++)
                data = itemsEncryptData[itemsKey[i].MethodData].Encrypt(data, itemsEncryptPassword[itemsKey[i].MethodPassword].Encrypt(itemsKey[i].Password));
            return data;
        }
        public byte[] Decrypt(byte[] data)
        {
            return Decrypt(data.ToHex()).HexStringToByteArray();
        }
        public string Decrypt(string data)
        {
            for (int i = itemsKey.Count-1; i >=0; i--)
                data = itemsEncryptData[itemsKey[i].MethodData].Decrypt(data, itemsEncryptPassword[itemsKey[i].MethodPassword].Encrypt(itemsKey[i].Password));
            return data;
        }
        public XmlDocument ToXml()
        {
            return ItemKey.ToXml(itemsKey);
        }

    }
}
