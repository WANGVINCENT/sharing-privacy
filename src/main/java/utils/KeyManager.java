package utils;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.Random;

import paillierp.key.KeyGen;
import paillierp.key.PaillierKey;
import paillierp.key.PaillierPrivateThresholdKey;

/**
 * 
 * @author wangnan
 *
 */
public class KeyManager {

	private static final int KEY_BITS_LENGTH = 256;
	private static final int NUM_PRIVATE_KEYS = 10;
	private static final int NUM_DECRYPTERS = 5;

	private static final String PUBLIC_KEY_NAME = "public.key";
	

	public static PaillierKey readFrom(String keyPath) {

		ObjectInputStream oosSK = null;

		try {
			oosSK = new ObjectInputStream(new BufferedInputStream(new FileInputStream(keyPath)));
			return (PaillierKey) oosSK.readObject();
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			try {
				oosSK.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		
		return null;
	}

	public static void main(String[] args) {

		PaillierPrivateThresholdKey[] keys = KeyGen.PaillierThresholdKey(KEY_BITS_LENGTH, NUM_PRIVATE_KEYS,
				NUM_DECRYPTERS, new Random().nextLong());

		PaillierKey publicKey = keys[0].getPublicKey();

		ObjectOutputStream oosSK = null;
		ObjectOutputStream oosPK = null;

		try {
			oosPK = new ObjectOutputStream(new BufferedOutputStream(new FileOutputStream(PUBLIC_KEY_NAME)));
			oosPK.writeObject(publicKey);
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			try {
				oosPK.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}

		for (PaillierPrivateThresholdKey key : keys) {
			String fileName = String.format("", key.getID());
			try {
				oosSK = new ObjectOutputStream(new BufferedOutputStream(new FileOutputStream(fileName)));
				oosSK.writeObject(key);
			} catch (Exception e) {
				e.printStackTrace();
			} finally {
				try {
					oosSK.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
		}
	}
}
