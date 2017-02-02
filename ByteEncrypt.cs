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
        /// It is based on hiding data from random data, avoid (char)0 or/and two consecutive 0x0 
        /// </summary>
        Disimulat,
        /// <summary>
        /// It is the Cesar algorithm adapted, avoid (char)0 or/and two consecutive 0x0 
        /// </summary>
        Cesar,
        /// <summary>
        /// It is a method to disorder bytes using a password, avoid (char)0 or/and two consecutive 0x0 
        /// </summary>
        Perdut,
	}
	public enum PasswordEncrypt
	{
		Md5,
		Sha256,
		Nothing
	}
	public enum LevelEncrypt
	{
		Lowest,
		Low,
		Normal,
		High,
		Highest
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
                case DataEncrypt.Perdut:
                    bytesEncrypted = ComunEncryptDecryptPerdut(bytes, password, level, order, true);
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
                case DataEncrypt.Perdut:
                    bytesDecrypted = ComunEncryptDecryptPerdut(bytes, password, level, order, false);
                    break;
			    default:throw new ArgumentOutOfRangeException("dataDecrypt");
			}

			return bytesDecrypted;
		}


        internal static int CalucloNumeroCirfrado(byte[] password, LevelEncrypt level, Ordre order, int pos)
		{
			return  Serializar.ToUShort(new byte[] { password.DameElementoActual(order, pos), password.DameElementoActual(order, pos + 1) }) * ((int)level+1)*2;
		}
        internal static int CalucloNumeroCirfrado(byte[] password, LevelEncrypt level, Ordre order, long pos)
        {
            return CalucloNumeroCirfrado(password, level, order, (int)(pos % int.MaxValue));
        }

        #region disimulat Encrypt
        private static byte[] EncryptDisimulat(byte[] bytes, byte[] password, LevelEncrypt level, Ordre order)
		{//por testear la ultima cosa :D
			byte[] bytesDisimulats;
            long longitudArray = bytes.LongLength;
			int numBytesRandom;
            long pos = 0;
            //calculo la longitud final
            for (long i = 0, f = bytes.LongLength; i <= f; i++)
            {
                longitudArray += CalucloNumeroCirfrado(password, level, order, pos);
                longitudArray++;//sumo el caracter a cifrar
                pos += 2;
            }
            longitudArray--;//el ultimo no existe :D
			bytesDisimulats = new byte[longitudArray];
            pos = 0;
			unsafe {
                byte* ptrBytesDisimulats,ptrBytes;
				bytesDisimulats.UnsafeMethod((unsBytesDisimulats) => bytes.UnsafeMethod(unsBytes => {
                    ptrBytesDisimulats = unsBytesDisimulats.PtrArray;
                    ptrBytes = unsBytes.PtrArray;
					for (long i = 0,f=longitudArray- CalucloNumeroCirfrado(password, level, order, bytes.LongLength); i < f; i++) {
						//recorro la array de bytes y pongo los bytes nuevos que tocan
						numBytesRandom = CalucloNumeroCirfrado(password, level, order, pos);
						for (int j = 0; j < numBytesRandom; j++) {
							*ptrBytesDisimulats = (byte)MiRandom.Next(byte.MaxValue+1);
                            ptrBytesDisimulats++;
						}
						*ptrBytesDisimulats = *ptrBytes;
                        ptrBytesDisimulats++;
                        ptrBytes++;
                        pos += 2;
					}
                    //para disumular el ultimo!
                    numBytesRandom = CalucloNumeroCirfrado(password, level, order, pos);
                    for (int j = 0; j < numBytesRandom; j++)
                    {
                        *ptrBytesDisimulats = (byte)MiRandom.Next(byte.MaxValue+1);
                        ptrBytesDisimulats++;
                    }
                }));
			}
			return bytesDisimulats;

        
		}
		private static byte[] DecryptDisimulat(byte[] bytes, byte[] password, LevelEncrypt level, Ordre order)
		{
			byte[] bytesTrobats;
			long longitudAux = bytes.LongLength;
			long longitud = 0;
            long pos = 0;
			//calculo la longitud original
			while (longitudAux > 0) {
				//le resto los caracteres random
				longitudAux -= CalucloNumeroCirfrado(password, level, order, pos);
				//quito el caracter original
				longitudAux--;
				//lo cuento
				longitud++;
                pos += 2;
			}
			bytesTrobats = new byte[longitud-2];//el ultimo es random tambien para disimular el ultimo real
            pos = 0;

            unsafe {
                byte* ptrBytes, ptrBytesTrobats;
				bytesTrobats.UnsafeMethod((unsBytesTrobats) => bytes.UnsafeMethod(unsBytes => {
                    ptrBytesTrobats = unsBytesTrobats.PtrArray;
                    ptrBytes = unsBytes.PtrArray;
                    for (long i = 0,f=longitud-1; i <f ; i++)
                    {
                        //recorro la array de bytes y pongo los bytes nuevos que tocan
                        ptrBytesTrobats += CalucloNumeroCirfrado(password, level, order,pos);
                        //me salto los bytes random
                        *ptrBytesTrobats = *ptrBytes;
                        //pongo el byte original
                        ptrBytesTrobats++;
                        //avanzo
                        ptrBytes++;
                        pos += 2;
                    }
                }));
			}
			return bytesTrobats;
		}
		#endregion
		#region Cesar encrypt 
		private static byte[] EncryptCesar(byte[] bytes, byte[] password, LevelEncrypt level, Ordre order)
		{
			byte[] bytesEncryptats = new byte[bytes.LongLength];
			int sumaCesar;
			unsafe {
                byte* ptrBytesOri, ptrBytesCesarEncrypt;
				bytesEncryptats.UnsafeMethod((unsByteEncriptat) => bytes.UnsafeMethod(unsBytes => {
                    ptrBytesOri = unsBytes.PtrArray;
                    ptrBytesCesarEncrypt = unsByteEncriptat.PtrArray;
					for (long i = 0,pos=0; i < unsBytes.Length; i++,pos+=2) {
                         sumaCesar = CalucloNumeroCirfrado(password, level, order, pos);
                        *ptrBytesCesarEncrypt = (byte)((*ptrBytesOri + sumaCesar) %(byte.MaxValue+1));
                        ptrBytesCesarEncrypt++;
                        ptrBytesOri++;
					}
				}));
			}
            return bytesEncryptats;
		}
		private static byte[] DecryptCesar(byte[] bytes, byte[] password, LevelEncrypt level, Ordre order)
        {
            byte[] bytesDesencryptats = new byte[bytes.LongLength];
			int restaCesar;
			int preByte;
			unsafe {
                byte* ptrBytesCesarEcnrypt, ptrBytesCesarDecrypt;
                bytesDesencryptats.UnsafeMethod((unsByteDesencryptat) => bytes.UnsafeMethod(unsBytes => {
                    ptrBytesCesarEcnrypt = unsBytes.PtrArray;
                    ptrBytesCesarDecrypt = unsByteDesencryptat.PtrArray;
					for (long i = 0,pos=0; i < unsBytes.Length; i++,pos+=2)
                    {
                        restaCesar = CalucloNumeroCirfrado(password, level, order, pos);
                        preByte = *ptrBytesCesarEcnrypt - restaCesar;

                        if (preByte < byte.MinValue)
                        {
                            preByte *= -1;
                            preByte %= (byte.MaxValue+1);
                            preByte *= -1;
                            if (preByte < byte.MinValue)
                                preByte += byte.MaxValue+1;

                        }
                       
                        //tengo lo que le han puesto de mas y tengo que quitarselo teniendo en cuenta que cuando llegue a 0 tiene que seguir 255
						*ptrBytesCesarDecrypt = (byte)preByte;
                        ptrBytesCesarDecrypt++;
                        ptrBytesCesarEcnrypt++;
					}
				}));
			}
			return bytesDesencryptats;
		}
        #endregion

        #region Perdut Encrypt

        private static byte[] ComunEncryptDecryptPerdut(byte[] bytes, byte[] password, LevelEncrypt level, Ordre order, bool toEncrypt)
        {
            bytes = bytes.SubArray(bytes.Length);//optimizar...si se puede claro

            unsafe
            {
                bytes.UnsafeMethod((ptrBytes) =>
                {
                        for (int i = 0, f = (int)level + 1; i < f; i++)//repito el proceso como nivel de seguridad :D
                        {
                            TractaPerdut(ptrBytes, password, level, order, toEncrypt);//si descifra ira hacia atrás
                        }

                });
                
            }
            return bytes;
        }

     

        private static unsafe void TractaPerdut(UnsafeArray ptrBytes, byte[] password, LevelEncrypt level, Ordre order, bool leftToRight)
        {//va bien :D
            byte aux;
            long posAux;
            int direccion = leftToRight ? 1 : -1;

            byte* ptBytes = ptrBytes.PtrArray;//creo que optmizo un poquito al no entrar en la propiedad :D
            for(long i= leftToRight ? 0 : ptrBytes.Length - 1,f= leftToRight ? ptrBytes.Length - 1: 0  ; leftToRight? i<=f: i >= f; i+=direccion)
            {
                posAux = (CalucloNumeroCirfrado(password, level, order, i)+i) % ptrBytes.Length;
                aux = ptBytes[posAux];
                ptBytes[posAux] = ptBytes[i];
                ptBytes[i] = aux;
            }
            
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
            List<byte[]> dataSplited = data.Split(bytesChange);
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
			for (int i = 1; i < dataSplited.Count - 1; i++) {
                
				passwordEncryptAct = passwordsEncrypt.DameElementoActual(order, numCanvis);
				dataEncryptAct = dataEncrypt.DameElementoActual(order, numCanvis);
				passwordActual = passwords.DameElementoActual(order, numCanvis);
				byteResultAux = metodo(dataSplited[i], passwordActual, dataEncryptAct, passwordEncryptAct, level, order).AddArray(bytesChange);
				dataResultSplited.Add(byteResultAux);
				numCanvis++;
                
			}
			if (dataSplited.Count > 1) {
				if (dataSplited[dataSplited.Count - 1].Length != 0) {//si no acaba en la marca es que hay bytes
					passwordEncryptAct = passwordsEncrypt.DameElementoActual(order, numCanvis);
					dataEncryptAct = dataEncrypt.DameElementoActual(order, numCanvis);
					passwordActual = passwords.DameElementoActual(order, numCanvis);
					byteResultAux = metodo(dataSplited[dataSplited.Count - 1], passwordActual, dataEncryptAct, passwordEncryptAct, level, order).AddArray(bytesChange);
					dataResultSplited.Add(byteResultAux);
      
				} else
					dataResultSplited.Add(bytesChange);//añado la marca a los bytes finales
			}

			return bytesResult.AddArray(dataResultSplited.ToArray());
		}
        //los bytes para el cambio tienen que ser unicos...y no se pueden dar dentro de los datos...
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
