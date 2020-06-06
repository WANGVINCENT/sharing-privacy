package agent;

import java.math.BigInteger;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.stream.Collectors;

import crypto.Encrypter;
import result.Worker6Result;

/**
 * 
 * @author wangnan
 *
 */
public class Worker6 implements Callable<Worker6Result> {

	private BigInteger scaledRandom;
	private List<BigInteger> ciphers;
	private Encrypter encrypter;

	public Worker6(BigInteger scaledRandom, List<BigInteger> ciphers, Encrypter encrypter) {
		this.scaledRandom = scaledRandom;
		this.ciphers = ciphers;
		this.encrypter = encrypter;
	}

	@Override
	public Worker6Result call() throws Exception {
		
		long s = System.nanoTime();
		List<BigInteger> ciphersWithRandom = this.ciphers.stream()
				.map(cipher -> this.encrypter.multiplyCiphers(cipher, this.scaledRandom)).collect(Collectors.toList());
		long e = System.nanoTime();
		return new Worker6Result(this.encrypter.addCiphers(ciphersWithRandom), e-s);
	}
}
