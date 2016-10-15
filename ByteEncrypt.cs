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
		/// <summary>
		/// It is based on hiding data from random data
		/// </summary>
		Disimulat,
		/// <summary>
		/// It is the Cesar algorithm adapted
		/// </summary>
		Cesar
	}
	public enum PasswordEncrypt
	{
		Md5,
		Sha256,
		Nothing
	}
	public enum LevelEncrypt
	{
		//la solucion al problema :D
		//los metodos tienen que cifrar teniendo en cuenta que un char son dos bytes y que byte[] puede ser impar y para que char no me de problema tiene que ser par siempre!!
		//poner valores par :) asi siempre sera par el cambio :D
		Lowest,
		Low = 2,
		Normal = 4,
		High = 8,
		Highest = 16
	}
	#endregion
	public static class ByteEncrypt
	{
		private delegate byte[] MetodoMultiKey(byte[] data, byte[] password, DataEncrypt dataEncrypt, PasswordEncrypt passwordEncrypt, LevelEncrypt level, Ordre order);
		public static readonly byte[] BytesChangeDefault = {
			0x0,
			0xFF,
			0xF4,
			0x5F
		};
		#region CanNotDecrypt
		public static byte[] EncryptNotReverse(this byte[] bytes, PasswordEncrypt passwordEncrypt = PasswordEncrypt.Md5)
		{
			if (bytes.Length != 0)
				switch (passwordEncrypt) {
					case PasswordEncrypt.Md5:
						bytes = bytes.Md5();
						break;
					case PasswordEncrypt.Sha256:
						bytes = bytes.Sha256();
						break;
					case PasswordEncrypt.Nothing:
						break;
					default:
						throw new ArgumentOutOfRangeException();
				}
			return bytes;
		}

		#endregion
		#region OneKey
		#region SobreCargaEncrypt
		public static byte[] Encrypt(this byte[] bytes, string password, DataEncrypt dataEncrypt = DataEncrypt.Cesar, LevelEncrypt level = LevelEncrypt.Normal, PasswordEncrypt passwordEncrypt = PasswordEncrypt.Nothing, Ordre order = Ordre.Consecutiu)
		{
			if (string.IsNullOrEmpty(password))
				throw new ArgumentException("se requiere una password", "password");
			return Encrypt(bytes, Serializar.GetBytes(password), dataEncrypt, passwordEncrypt, level, order);
		}
		public static byte[] Encrypt(this byte[] bytes, byte[] password, DataEncrypt dataEncrypt = DataEncrypt.Cesar, LevelEncrypt level = LevelEncrypt.Normal, PasswordEncrypt passwordEncrypt = PasswordEncrypt.Nothing, Ordre order = Ordre.Consecutiu)
		{
			if (password == null)
				throw new ArgumentNullException("password", "se requiere una password");
			return Encrypt(bytes, password.EncryptNotReverse(passwordEncrypt), dataEncrypt, level, order);
		}
		internal static byte[] Encrypt(this byte[] bytes, byte[] password, DataEncrypt dataEncrypt, PasswordEncrypt passwordEncrypt, LevelEncrypt level, Ordre order = Ordre.Consecutiu)
		{
			if (password == null)
				throw new ArgumentNullException("password", "se requiere una password");
			return Encrypt(bytes, password.EncryptNotReverse(passwordEncrypt), dataEncrypt, level, order);
		}
		#endregion
		internal static byte[] Encrypt(this byte[] bytes, byte[] password, DataEncrypt dataEncrypt, LevelEncrypt level, Ordre order)
		{
			byte[] bytesEncrypted = null;
		  
			switch (dataEncrypt) {
				case DataEncrypt.Cesar:
					bytesEncrypted = EncryptCesar(bytes, password, level, order);
					break;
				case DataEncrypt.Disimulat:
					bytesEncrypted = EncryptDisimulat(bytes, password, level, order);
					break;
			    default:throw new ArgumentOutOfRangeException("dataEncrypt");
			}
			
			return bytesEncrypted;
		}
		#region SobreCargaDecrypt
		public static byte[] Decrypt(this byte[] bytes, string password, DataEncrypt dataEncrypt = DataEncrypt.Cesar, LevelEncrypt level = LevelEncrypt.Normal, PasswordEncrypt passwordEncrypt = PasswordEncrypt.Nothing, Ordre order = Ordre.Consecutiu)
		{
			if (string.IsNullOrEmpty(password))
				throw new ArgumentException("se requiere una password", "password");
			return Decrypt(bytes, Serializar.GetBytes(password), dataEncrypt, passwordEncrypt, level, order);
		}
		public static byte[] Decrypt(this byte[] bytes, byte[] password, DataEncrypt dataEncrypt = DataEncrypt.Cesar, LevelEncrypt level = LevelEncrypt.Normal, PasswordEncrypt passwordEncrypt = PasswordEncrypt.Nothing, Ordre order = Ordre.Consecutiu)
		{
			if (password == null)
				throw new ArgumentNullException("password", "se requiere una password");
			return Decrypt(bytes, password.EncryptNotReverse(passwordEncrypt), dataEncrypt, level, order);
		}
		internal static byte[] Decrypt(this byte[] bytes, byte[] password, DataEncrypt dataEncrypt, PasswordEncrypt passwordEncrypt, LevelEncrypt level, Ordre order)
		{
			if (password == null)
				throw new ArgumentNullException("password", "se requiere una password");
			return Decrypt(bytes, password.EncryptNotReverse(passwordEncrypt), dataEncrypt, level, order);
		}
		#endregion
		internal static byte[] Decrypt(this byte[] bytes, byte[] password, DataEncrypt dataDecrypt, LevelEncrypt level, Ordre order)
		{
			if (password.Length == 0)
				throw new ArgumentException("Se requiere una password de longitud > 0");
			byte[] bytesDecrypted = null;
			
			switch (dataDecrypt) {
				case DataEncrypt.Cesar:
					bytesDecrypted = DecryptCesar(bytes, password, level, order);
					break;
				case DataEncrypt.Disimulat:
					bytesDecrypted = DecryptDisimulat(bytes, password, level, order);
					break;
			    default:throw new ArgumentOutOfRangeException("dataDecrypt");
			}

			return bytesDecrypted;
		}


		private static int CalucloNumeroCirfrado(byte[] password, LevelEncrypt level, Ordre order, int i)
		{
			return  password.DameElementoActual(order, i) * (int)level;
		}
		#region disimulat Encrypt
		private static byte[] EncryptDisimulat(byte[] bytes, byte[] password, LevelEncrypt level, Ordre order)
		{
			byte[] bytesDisimulats;
			long longitudArray = bytes.Length;
			int numBytesRandom;
			//calculo la longitud final
			for (int i = 0; i < bytes.Length; i++)
				longitudArray += CalucloNumeroCirfrado(password, level, order, i);
			bytesDisimulats = new byte[longitudArray];
			unsafe {
				bytesDisimulats.UnsafeMethod((unsBytesDisimulats) => bytes.UnsafeMethod(unsBytes => {
					for (int i = 0; i < unsBytes.Length; i++) {
						//recorro la array de bytes y pongo los bytes nuevos que tocan
						numBytesRandom = CalucloNumeroCirfrado(password, level, order, i);
						for (int j = 0; j < numBytesRandom; j++) {
							*unsBytesDisimulats.PtrArray = (byte)MiRandom.Next(byte.MaxValue);
							unsBytesDisimulats.PtrArray++;
						}
						*unsBytesDisimulats.PtrArray = *unsBytes.PtrArray;
						unsBytesDisimulats.PtrArray++;
						unsBytes.PtrArray++;
					}
				}));
			}
			return bytesDisimulats;

        
		}
		private static byte[] DecryptDisimulat(byte[] bytes, byte[] password, LevelEncrypt level, Ordre order)
		{
			byte[] bytesTrobats;
			long longitudAux = bytes.Length;
			long longitud = 0;
			int j = 0;
			//calculo la longitud original
			while (longitudAux > 0) {
				//le resto los caracteres random
				longitudAux -= CalucloNumeroCirfrado(password, level, order, j++);
				//quito el caracter original
				longitudAux--;
				//lo cuento
				longitud++;
			}
			bytesTrobats = new byte[longitud];
			unsafe {
				bytesTrobats.UnsafeMethod((unsBytesTrobats) => bytes.UnsafeMethod(unsBytes => {
					for (int i = 0; i < bytesTrobats.Length; i++) {
						//recorro la array de bytes y pongo los bytes nuevos que tocan
						unsBytes.PtrArray += CalucloNumeroCirfrado(password, level, order, i);
						//me salto los bytes random
						*unsBytesTrobats.PtrArray = *unsBytes.PtrArray;
						//pongo el byte original
						unsBytesTrobats.PtrArray++;
						//avanzo
						unsBytes.PtrArray++;
					}
				}));
			}
			return bytesTrobats;
		}
		#endregion
		#region Cesar encrypt
		private static byte[] EncryptCesar(byte[] bytes, byte[] password, LevelEncrypt level, Ordre order)
		{//no funciona bien...
			byte[] bytesEncryptats = new byte[bytes.Length];
			int sumaCesar;
			unsafe {
				bytesEncryptats.UnsafeMethod((unsByteEncriptat) => bytes.UnsafeMethod(unsBytes => {
					for (int i = 0; i < unsBytes.Length; i++) {
						sumaCesar = CalucloNumeroCirfrado(password, level, order, i);
						*unsByteEncriptat.PtrArray = (byte)((*unsBytes.PtrArray + sumaCesar) % byte.MaxValue);
						unsByteEncriptat.PtrArray++;
						unsBytes.PtrArray++;
					}
				}));
			}
			return bytesEncryptats;
		}
		private static byte[] DecryptCesar(byte[] bytes, byte[] password, LevelEncrypt level, Ordre order)
		{//no funciona bien...
			byte[] bytesDesencryptats = new byte[bytes.Length];
			int restaCesar;
			int preByte;
			unsafe {
				bytesDesencryptats.UnsafeMethod((unsByteDesencryptat) => bytes.UnsafeMethod(unsBytes => {
					for (int i = 0; i < unsBytes.Length; i++) {
						restaCesar = CalucloNumeroCirfrado(password, level, order, i);
						preByte = (*unsBytes.PtrArray - restaCesar);
						//lo tengo que restar y tirar atras para volver al estado
						if (preByte < 0) {
							preByte = Math.Abs(preByte);
							preByte = preByte % byte.MaxValue;
							if(preByte>0)
							  preByte = byte.MaxValue - preByte;
						}
						*unsByteDesencryptat.PtrArray = (byte)preByte;
						unsByteDesencryptat.PtrArray++;
						unsBytes.PtrArray++;
					}
				}));
			}
			return bytesDesencryptats;
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
			byteResultAux = metodo(dataSplited[0], passwordActual, dataEncryptAct, passwordEncryptAct, level, order);
			if (data.BuscarArray(bytesChange) > -1)//si tiene marca la pongo
             byteResultAux = byteResultAux.AddArray(bytesChange);
			dataResultSplited.Add(byteResultAux);
			numCanvis++;
			for (int i = 1; i < dataSplited.Length - 1; i++) {
                
				passwordEncryptAct = passwordsEncrypt.DameElementoActual(order, numCanvis);
				dataEncryptAct = dataEncrypt.DameElementoActual(order, numCanvis);
				passwordActual = passwords.DameElementoActual(order, numCanvis);
				byteResultAux = metodo(dataSplited[i], passwordActual, dataEncryptAct, passwordEncryptAct, level, order).AddArray(bytesChange);
				dataResultSplited.Add(byteResultAux);
				numCanvis++;
                
			}
			if (dataSplited.Length > 1) {
				if (dataSplited[dataSplited.Length - 1].Length != 0) {//si no acaba en la marca es que hay bytes
					passwordEncryptAct = passwordsEncrypt.DameElementoActual(order, numCanvis);
					dataEncryptAct = dataEncrypt.DameElementoActual(order, numCanvis);
					passwordActual = passwords.DameElementoActual(order, numCanvis);
					byteResultAux = metodo(dataSplited[dataSplited.Length - 1], passwordActual, dataEncryptAct, passwordEncryptAct, level, order).AddArray(bytesChange);
					dataResultSplited.Add(byteResultAux);
      
				} else
					dataResultSplited.Add(bytesChange);//añado la marca a los bytes finales
			}

			return bytesResult.AddArray(dataResultSplited.ToArray());
		}

		#region SobreCargaEncrypt
		public static byte[] Encrypt(this byte[] bytes, string[] passwords, DataEncrypt dataEncrypt = DataEncrypt.Cesar, PasswordEncrypt passwordEncrypt = PasswordEncrypt.Md5, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu)
		{
			return Encrypt(bytes, passwords, BytesChangeDefault, new DataEncrypt[] { dataEncrypt }, new PasswordEncrypt[] { passwordEncrypt }, level, escogerKey);
		}
		public static byte[] Encrypt(this byte[] bytes, string[] passwords, DataEncrypt[] dataEncrypt, PasswordEncrypt passwordEncrypt = PasswordEncrypt.Md5, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu)
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

		public static byte[] Encrypt(this byte[] bytes, byte[][] passwords, DataEncrypt dataEncrypt = DataEncrypt.Cesar, PasswordEncrypt passwordEncrypt = PasswordEncrypt.Md5, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu)
		{
			return Encrypt(bytes, passwords, BytesChangeDefault, new DataEncrypt[] { dataEncrypt }, new PasswordEncrypt[] { passwordEncrypt }, level, escogerKey);
		}
		public static byte[] Encrypt(this byte[] bytes, byte[][] passwords, DataEncrypt[] dataEncrypt, PasswordEncrypt passwordEncrypt = PasswordEncrypt.Md5, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu)
		{
			return Encrypt(bytes, passwords, BytesChangeDefault, dataEncrypt, new PasswordEncrypt[] { passwordEncrypt }, level, escogerKey);
		}
		public static byte[] Encrypt(this byte[] bytes, byte[][] passwords, PasswordEncrypt[] passwordEncrypt, DataEncrypt dataEncrypt = DataEncrypt.Cesar, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu)
		{
			return Encrypt(bytes, passwords, BytesChangeDefault, new DataEncrypt[] { dataEncrypt }, passwordEncrypt, level, escogerKey);
		}

		public static byte[] Encrypt(this byte[] bytes, byte[][] passwords, DataEncrypt[] dataEncrypt, PasswordEncrypt[] passwordEncrypt, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu)
		{
			return Encrypt(bytes, passwords, BytesChangeDefault, dataEncrypt, passwordEncrypt, level, escogerKey);
		}
		public static byte[] Encrypt(this byte[] bytes, string[] passwords, byte[] bytesChange, DataEncrypt dataEncrypt = DataEncrypt.Cesar, PasswordEncrypt passwordEncrypt = PasswordEncrypt.Md5, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu)
		{
			return Encrypt(bytes, passwords, bytesChange, new DataEncrypt[] { dataEncrypt }, new PasswordEncrypt[] { passwordEncrypt }, level, escogerKey);
		}
		public static byte[] Encrypt(this byte[] bytes, string[] passwords, byte[] bytesChange, DataEncrypt[] dataEncrypt, PasswordEncrypt passwordEncrypt = PasswordEncrypt.Md5, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu)
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

		public static byte[] Encrypt(this byte[] bytes, byte[][] passwords, byte[] bytesChange, DataEncrypt dataEncrypt = DataEncrypt.Cesar, PasswordEncrypt passwordEncrypt = PasswordEncrypt.Md5, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu)
		{
			return Encrypt(bytes, passwords, bytesChange, new DataEncrypt[] { dataEncrypt }, new PasswordEncrypt[] { passwordEncrypt }, level, escogerKey);
		}
		public static byte[] Encrypt(this byte[] bytes, byte[][] passwords, byte[] bytesChange, DataEncrypt[] dataEncrypt, PasswordEncrypt passwordEncrypt = PasswordEncrypt.Md5, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu)
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
		public static byte[] Decrypt(this byte[] bytes, string[] passwords, DataEncrypt dataEncrypt = DataEncrypt.Cesar, PasswordEncrypt passwordEncrypt = PasswordEncrypt.Md5, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu)
		{
			return Decrypt(bytes, passwords, new DataEncrypt[] { dataEncrypt }, new PasswordEncrypt[] { passwordEncrypt }, level, escogerKey);
		}
		public static byte[] Decrypt(this byte[] bytes, string[] passwords, DataEncrypt[] dataEncrypt, PasswordEncrypt passwordEncrypt = PasswordEncrypt.Md5, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu)
		{
			return Decrypt(bytes, passwords, dataEncrypt, new PasswordEncrypt[] { passwordEncrypt }, level, escogerKey);
		}
		public static byte[] Decrypt(this byte[] bytes, string[] passwords, PasswordEncrypt[] passwordEncrypt, DataEncrypt dataEncrypt = DataEncrypt.Cesar, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu)
		{
			return Decrypt(bytes, passwords, new DataEncrypt[] { dataEncrypt }, passwordEncrypt, level, escogerKey);
		}
		public static byte[] Decrypt(this byte[] bytes, string[] passwords, DataEncrypt[] dataEncrypt, PasswordEncrypt[] passwordEncrypt, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu)
		{
			return Decrypt(bytes, passwords, BytesChangeDefault, dataEncrypt, passwordEncrypt, level, escogerKey);
		}
		public static byte[] Decrypt(this byte[] bytes, byte[][] passwords, DataEncrypt dataEncrypt = DataEncrypt.Cesar, PasswordEncrypt passwordEncrypt = PasswordEncrypt.Md5, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu)
		{
			return Decrypt(bytes, passwords, new DataEncrypt[] { dataEncrypt }, new PasswordEncrypt[] { passwordEncrypt }, level, escogerKey);
		}
		public static byte[] Decrypt(this byte[] bytes, byte[][] passwords, DataEncrypt[] dataEncrypt, PasswordEncrypt passwordEncrypt = PasswordEncrypt.Md5, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu)
		{
			return Decrypt(bytes, passwords, dataEncrypt, new PasswordEncrypt[] { passwordEncrypt }, level, escogerKey);
		}
		public static byte[] Decrypt(this byte[] bytes, byte[][] passwords, PasswordEncrypt[] passwordEncrypt, DataEncrypt dataEncrypt = DataEncrypt.Cesar, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu)
		{
			return Decrypt(bytes, passwords, new DataEncrypt[] { dataEncrypt }, passwordEncrypt, level, escogerKey);
		}

		public static byte[] Decrypt(this byte[] bytes, byte[][] passwords, DataEncrypt[] dataEncrypt, PasswordEncrypt[] passwordEncrypt, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu)
		{
			return Decrypt(bytes, passwords, BytesChangeDefault, dataEncrypt, passwordEncrypt, level, escogerKey);
		}
		public static byte[] Decrypt(this byte[] bytes, string[] passwords, byte[] bytesChange, DataEncrypt dataEncrypt = DataEncrypt.Cesar, PasswordEncrypt passwordEncrypt = PasswordEncrypt.Md5, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu)
		{
			return Decrypt(bytes, passwords, bytesChange, new DataEncrypt[] { dataEncrypt }, new PasswordEncrypt[] { passwordEncrypt }, level, escogerKey);
		}
		public static byte[] Decrypt(this byte[] bytes, string[] passwords, byte[] bytesChange, DataEncrypt[] dataEncrypt, PasswordEncrypt passwordEncrypt = PasswordEncrypt.Md5, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu)
		{
			return Decrypt(bytes, passwords, bytesChange, dataEncrypt, new PasswordEncrypt[] { passwordEncrypt }, level, escogerKey);
		}
		public static byte[] Decrypt(this byte[] bytes, string[] passwords, byte[] bytesChange, PasswordEncrypt[] passwordEncrypt, DataEncrypt dataEncrypt = DataEncrypt.Cesar, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu)
		{
			return Decrypt(bytes, passwords, bytesChange, new DataEncrypt[] { dataEncrypt }, passwordEncrypt, level, escogerKey);
		}
		public static byte[] Decrypt(this byte[] bytes, string[] passwords, byte[] bytesChange, DataEncrypt[] dataEncrypt, PasswordEncrypt[] passwordEncrypt, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu)
		{
			if (passwords == null || dataEncrypt == null || passwordEncrypt == null)
				throw new ArgumentNullException();
			List<byte[]> passwordBytes = new List<byte[]>();
			for (int i = 0; i < passwords.Length; i++)
				passwordBytes.Add(Serializar.GetBytes(passwords[i]));
			return Decrypt(bytes, passwordBytes.ToArray(), bytesChange, dataEncrypt, passwordEncrypt, level, escogerKey);
		}
		public static byte[] Decrypt(this byte[] bytes, byte[][] passwords, byte[] bytesChange, DataEncrypt dataEncrypt = DataEncrypt.Cesar, PasswordEncrypt passwordEncrypt = PasswordEncrypt.Md5, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu)
		{
			return Decrypt(bytes, passwords, bytesChange, new DataEncrypt[] { dataEncrypt }, new PasswordEncrypt[] { passwordEncrypt }, level, escogerKey);
		}
		public static byte[] Decrypt(this byte[] bytes, byte[][] passwords, byte[] bytesChange, DataEncrypt[] dataEncrypt, PasswordEncrypt passwordEncrypt = PasswordEncrypt.Md5, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu)
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
