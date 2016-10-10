using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Text;

using System.Collections;
using Gabriel.Cat.Extension;

namespace Gabriel.Cat.Seguretat
{
	public enum XifratImg
	{
		Normal
	}
	public struct XifratImgNivell
	{
		XifratImg xifrat;
        LevelEncrypt nivell;

		public XifratImgNivell(XifratImg xifrat, LevelEncrypt nivell)
		{
			this.xifrat = xifrat;
			this.nivell = nivell;
		}

		public XifratImg Xifrat {
			get {
				return xifrat;
			}

		}

		public LevelEncrypt Nivell {
			get {
				return nivell;
			}
		}
	}
	public static class XifraBitmap
	{
		const int BITSBYTE = 8;
        /// <summary>
        /// Sirve para saber los bytes que necesita una imagen tener para contener los datos
        /// </summary>
        /// <param name="dades"></param>
        /// <param name="nivell"></param>
        /// <returns></returns>
        public static int BytesImgMin(this byte[] dades, LevelEncrypt nivell)
        {
            return (dades.Length * BITSBYTE) * ((int)nivell + 1); 
        }
        /// <summary>
        /// sirve para saber cuantos bytes puede contener una imagen
        /// </summary>
        /// <param name="bmp"></param>
        /// <param name="nivell"></param>
        /// <returns></returns>
        public static int MaxBytesImg(this Bitmap bmp, LevelEncrypt nivell)
        {
            return bmp.LengthBytes() / (((int)nivell + 1) * BITSBYTE);
        }
        public static Bitmap Encrypt(this string text, XifratImg xifrat, LevelEncrypt nivell)
		{
			return Serializar.GetBytes(text).Encrypt(xifrat, nivell);
		}
		public static Bitmap Encrypt(this byte[] dades, XifratImg xifrat, LevelEncrypt nivell)
		{
            //hago una img con pixeles random
            int totalBytesImg = dades.BytesImgMin(nivell);
			int height =Convert.ToInt32( Math.Sqrt(totalBytesImg)), width = (totalBytesImg / height)+1;
			Bitmap imgRandom = new Bitmap(width, height);
			imgRandom.RandomPixels();
			imgRandom.Encrypt(xifrat, nivell, dades);
			return imgRandom;
		}

		public static void Encrypt(this Bitmap img, XifratImg xifrat, LevelEncrypt nivell, string text)
		{
			img.Encrypt(xifrat, nivell, Serializar.GetBytes(text));
		}
		public static void Encrypt(this Bitmap img, XifratImg xifrat, LevelEncrypt nivell, byte[] dades)
		{
			bool[] bitsAPoner;
			int longitudImg;
			int auxByte;
			int longitud=dades.Length;
			switch (xifrat) {
			//le mezclo los datos
				case XifratImg.Normal:/*dades = dades;*/
					break;//ejemplo

			}
			//pone los bytes en la imagen
			bitsAPoner = Serializar.GetBytes(longitud).AfegirValors(dades).ToBits();
			
			if (img.LengthBytes() < bitsAPoner.Length * ((int)nivell + 1))
				throw new Exception("La imatge no pot contenir les dades amb el nivell de seguretat posat!");
			unsafe {
				img.TrataBytes((MetodoTratarBytePointer)((imgBytes) => {
					longitudImg = img.LengthBytes();
					auxByte = 0;
				                                         	
					for (int j = 0, i = 0, incremento = ((int)nivell + 1); i < bitsAPoner.Length; j += incremento, i++) {//pongo la longitud de los datos y luego los datos
						if (bitsAPoner[i]) {
							auxByte = imgBytes[j];

							//tiene que ser true
							if (auxByte % 2 == 0) {
								auxByte++;
								imgBytes[j] = (byte)auxByte;
							}
				                                         			
						} else {
							auxByte = imgBytes[j];
							//tiene que ser false
							if (auxByte % 2 != 0) {
								auxByte--;
								imgBytes[j] = (byte)auxByte;
							}
						}
					}


				}
				));
			}


		}

		public static byte[] Decrypt(this Bitmap img, XifratImg xifrat, LevelEncrypt nivell)
		{
		 	
			bool[] dadesBits = null;
			byte[] dades = null;
			bool[] bitsLongitudDades = new bool[ BITSBYTE * 4];
			byte[] bytesLongitudDades;
			int longitudDades;
			int incremento = ((int)nivell + 1);
			unsafe {
				img.TrataBytes((MetodoTratarBytePointer)((bytesImg) => {
				                                         	
					//leo la longitud
					for (int i = 0, k = 0; k < bitsLongitudDades.Length; i += incremento,k++) {
						bitsLongitudDades[k] = bytesImg[i] % 2 != 0;
					}
					bytesLongitudDades = bitsLongitudDades.ToByteArray();
					longitudDades = Serializar.ToInt(bytesLongitudDades);
					dadesBits = new bool[longitudDades*BITSBYTE];
					//leo hasta acabar tal longitud
					for (int i = incremento * bitsLongitudDades.Length, f = i + (dadesBits.Length * incremento), k = 0; i<f; i += incremento,k++) {
						dadesBits[k] = bytesImg[i] % 2 != 0;
					}
					dades = dadesBits.ToByteArray();
				}));
			}
			switch (xifrat) {
			//lo descifro

				case XifratImg.Normal:/* dades = dades;*/
					break;//ejemplo
			}

			return dades;
		}





	}
}
