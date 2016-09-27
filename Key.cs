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
			public class ItemKeyBinary : Gabriel.Cat.Binaris.ElementoComplejoBinario
			{
				public ItemKeyBinary()
				{
					//inicializo la parte del formato aqui

					base.PartesElemento.Afegir(Binaris.ElementoBinario.ElementosTipoAceptado(Serializar.TiposAceptados.Int));
					base.PartesElemento.Afegir(Binaris.ElementoBinario.ElementosTipoAceptado(Serializar.TiposAceptados.Int));
					base.PartesElemento.Afegir(Binaris.ElementoBinario.ElementosTipoAceptado(Serializar.TiposAceptados.String));
				}
				public override byte[] GetBytes(object obj)
				{
					ItemKey item = obj as ItemKey;
					byte[] bytes = new byte[0];
					return bytes.AddArray(base.PartesElemento[0].GetBytes(item.MethodData), base.PartesElemento[1].GetBytes(item.MethodPassword), base.PartesElemento[2].GetBytes(item.Password));
				}
            

				protected override object GetObject(object[] parts)
				{
					return new ItemKey() {
						MethodData = (int)parts[0],
						MethodPassword = (int)parts[1],
						Password = (string)parts[2]
					};
				}
				public ItemKey GetItemKey(Stream strBytes)
				{
					return GetObject(strBytes) as ItemKey;
				}
				public ItemKey GetItemKey(byte[] bytes)
				{
					return GetItemKey(new MemoryStream(bytes));
				}
			}
			public static readonly ItemKeyBinary ItemKeyBin = new ItemKeyBinary();
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
				Password = Serializar.ToString(nodeItem.ChildNodes[2].InnerText.HexStringToByteArray());
			}
			public ItemKey(Stream strItems)
			{
				ItemKey item = ItemKeyBin.GetItemKey(strItems);
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
				nodeString.Append(Serializar.GetBytes(Password).ToHex());
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

               
		}
		public class ItemEncryptationData
		{
			public delegate string MethodEncryptReversible(string data, string password, bool encrypt = true);
            

			public MethodEncryptReversible MethodData { get; set; }

			public ItemEncryptationData(MethodEncryptReversible methodData)
			{
				MethodData = methodData;

			}
			public string Encrypt(string data, string key)
			{
				return MethodData(data, key);
			}
			public string Decrypt(string data, string key)
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

		public class KeyBinary : Binaris.ElementoIEnumerableBinario
		{
			public KeyBinary()
				: base(ItemKey.ItemKeyBin, LongitudBinaria.Long)
			{

			}
			public override byte[] GetBytes(object obj)
			{
				Key key = obj as Key;

				if (key == null)
					throw new ArgumentException();
				return base.GetBytes(key.itemsKey);
			}
			public Key GetKey(Stream strObj)
			{
				Object objs=GetObject(strObj);
				return new Key((objs as IEnumerable<object>).Casting<ItemKey>());
			}
			public Key GetKey(byte[] bytesObj)
			{
				return GetKey(new MemoryStream(bytesObj));
			}

		}

		public static readonly KeyBinary KeyBin = new Key.KeyBinary();
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
        public Key(string fileKey,params string[] keysToDecrypt ) : this(fileKey,GetKey(keysToDecrypt))
        {

        }
        public Key(FileInfo fileKey,params string[] keysToDecrypt):this(fileKey, GetKey(keysToDecrypt))
        {
        }
        public Key(string fileKey, Key keyToDecrypt = null):this(new FileInfo(fileKey),keyToDecrypt)
        { }
        public Key(FileInfo fileKey,Key keyToDecrypt=null)
			: this(fileKey.GetStream(),keyToDecrypt)
		{
		}
		public Key(Stream strOneKey, Key keyToDecrypt = null)
			: this()
		{
            Stream strDecrypted;
            Key key;
			try {
				if (keyToDecrypt != null) {
					strDecrypted = new MemoryStream(keyToDecrypt.Decrypt(strOneKey.GetAllBytes()));
					strDecrypted.Position = strOneKey.Position;
				} else
					strDecrypted = strOneKey;
				key = KeyBin.GetKey(strDecrypted);
				itemsKey = key.itemsKey;
				strOneKey.Position = strDecrypted.Position;
			} catch (Exception m) {
				throw new Exception("La llave para descifrar los datos de la llave a cargar no es la correcta!",m);
			}
		}
		public Key(byte[] bytesKey, Key keyToDecrypt = null)
			: this(new MemoryStream(bytesKey),keyToDecrypt)
		{
		}
		public List<ItemKey> ItemsKey {
			get { return itemsKey; }
		}

		public List<ItemEncryptationData> ItemsEncryptData {
			get {
				return itemsEncryptData;
			}
		}
		public List<ItemEncryptationPassword> ItemsEncryptPassword {
			get {
				return itemsEncryptPassword;
			}
		}
		public byte[] Encrypt(byte[] data)
		{
			Hex dataHex = data.ToHex();
			return Serializar.GetBytes(Encrypt(dataHex));
		}
		public string Encrypt(string data)
		{
			ItemEncryptationData itemEncryptData;
			ItemEncryptationPassword itemEncryptPassword;
			for (int i = 0, f = itemsKey.Count; i < f; i++){
				itemEncryptData=itemsEncryptData[itemsKey[i].MethodData];
				itemEncryptPassword=itemsEncryptPassword[itemsKey[i].MethodPassword];
				data = itemEncryptData.Encrypt(data, itemEncryptPassword.Encrypt(itemsKey[i].Password));
			}
			return data;
		}
		public byte[] Decrypt(byte[] data)
		{
			string hexDecrypted = Decrypt(Serializar.ToString(data));
			byte[] bytesDecrypted;
			try {
				bytesDecrypted = hexDecrypted.HexStringToByteArray();
			} catch {
				throw new Exception("los datos no se pueden descifrar con esta llave");
			}
			return bytesDecrypted;
		}
		public string Decrypt(string data)
		{
			ItemEncryptationData itemEncryptData;
			ItemEncryptationPassword itemEncryptPassword;
			for (int i = itemsKey.Count - 1; i >= 0; i--){ 
				
				itemEncryptData=itemsEncryptData[itemsKey[i].MethodData];
				itemEncryptPassword=itemsEncryptPassword[itemsKey[i].MethodPassword];
				data = itemEncryptData.Decrypt(data, itemEncryptPassword.Encrypt(itemsKey[i].Password));
			}
			return data;
		}
		public XmlDocument ToXml()
		{
			return ItemKey.ToXml(itemsKey);
		}

        public byte[] GetBytes(params string[] keysToEncryptData)
        {
            return GetBytes(GetKey(keysToEncryptData));
        }
		public  byte[] GetBytes(Key keyToEncryptData=null)
		{
			byte[] bytes= KeyBin.GetBytes(this);
            if (keyToEncryptData != null)
                bytes = keyToEncryptData.Encrypt(bytes);
            return bytes;
		}

        public static Key GetKey(params string[] passwords)
        {
            return GetKey((IEnumerable<string>)passwords);
        }
        public static Key GetKey(IEnumerable<string> passwords)
        {
            if (passwords == null)
                throw new ArgumentNullException();
            Key key = new Key();
            key.ItemsEncryptData.Add(new ItemEncryptationData(MetodoCesar));
            key.ItemsEncryptPassword.Add(new ItemEncryptationPassword(MetodoHash));
            foreach(string password in passwords)
            {
                if (String.IsNullOrEmpty(password))
                    throw new ArgumentException("se necesita una password, no puede ser ni null ni empty");
                key.ItemsKey.Add(new ItemKey() { Password = password });
            }
            return key;
        }

        private static string MetodoCesar(string data, string password, bool encrypt)
        {
            string dataOut;
            if(encrypt)
            {
                dataOut = data.Xifra(XifratText.Cesar, NivellXifrat.MoltAlt, password);
            }else
            {
                dataOut = data.Desxifra(XifratText.Cesar, NivellXifrat.MoltAlt, password);
            }
            return dataOut;
        }

        private static string MetodoHash(string password)
        {
            return Serializar.GetBytes(password).Hash();
        }
    }
}
