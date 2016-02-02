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
		NivellXifrat nivell;

		public XifratImgNivell(XifratImg xifrat, NivellXifrat nivell)
		{
			this.xifrat = xifrat;
			this.nivell = nivell;
		}

		public XifratImg Xifrat {
			get {
				return xifrat;
			}

		}

		public NivellXifrat Nivell {
			get {
				return nivell;
			}
		}
	}
	public static class XifraBitmap
	{
		const int BITSBYTE = 8;

		public static Bitmap Xifra(this string text, XifratImg xifrat, NivellXifrat nivell)
		{

			return Serializar.GetBytes(text).Xifra(xifrat, nivell);
		}
		public static Bitmap Xifra(this byte[] dades, XifratImg xifrat, NivellXifrat nivell)
		{
			//por probar, mirar que lo haga bien :)
			//    creo una imagen random que quepa lo que quiero
			int totalBytesImg = (dades.Length* BITSBYTE) * ((int)nivell + 1) ;
			int height = totalBytesImg / 2, width = totalBytesImg - height;
			Bitmap imgRandom = new Bitmap(width, height);
			imgRandom.RandomPixels();
			imgRandom.Xifra(xifrat, nivell, dades);
			return imgRandom;
		}
		public static void Xifra(this Bitmap img, XifratImg xifrat, NivellXifrat nivell, string text)
		{
			img.Xifra(xifrat, nivell, Serializar.GetBytes(text));
		}
		public static void Xifra(this Bitmap img, XifratImg xifrat, NivellXifrat nivell, byte[] dades)
		{
			bool[] bitsAPoner;
			int longitudImg;
			int auxByte;
			switch (xifrat) {
			//le mezclo los datos
				case XifratImg.Normal:/*dades = dades;*/
					break;//ejemplo

			}
			//pone los bytes en la imagen
			bitsAPoner = Serializar.GetBytes(dades.Length).AfegirValors(dades).ToBits();
			
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

		public static byte[] Desxifra(this Bitmap img, XifratImg xifrat, NivellXifrat nivell)
		{
			
			bool[] dadesBits = null;
			byte[] dades = null;
			bool[] bitsLongitudDades = new bool[ BITSBYTE * 4];
			byte[] bytesLongitudDades;
			int longitudDades;
			int incremento = ((int)nivell + 1) * BITSBYTE;
			unsafe {
				img.TrataBytes((MetodoTratarBytePointer)((bytesImg) => {
				                                         	
					//leo la longitud
					for (int i = 0, k = 0; k < bitsLongitudDades.Length; i += incremento,k++) {
						bitsLongitudDades[k] = bytesImg[i] % 2 != 0;
					}
					bytesLongitudDades = bitsLongitudDades.ToByteArray();
					longitudDades = Serializar.ToInt(bytesLongitudDades);
					dadesBits = new bool[longitudDades];
					//leo hasta acabar tal longitud
					for (int i = incremento * bitsLongitudDades.Length, f = i + (dadesBits.Length * incremento), k = 0; k < dadesBits.Length / 8; i += incremento,k++) {
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

		public static int MaxBytesXifrat(this Bitmap bmp, NivellXifrat nivell)
		{
			return bmp.LengthBytes() / (((int)nivell + 1) * BITSBYTE);
		}




	}
}
