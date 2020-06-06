package stage_threshold;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.stream.Collectors;

import com.google.common.collect.Lists;

import agent.Config;
import agent.Operator;
import agent.User;
import agent.Worker4;
import agent.Worker5;
import agent.Worker6;
import paillierp.Paillier;
import paillierp.key.KeyGen;
import paillierp.key.PaillierPrivateThresholdKey;
import paillierp.zkp.DecryptionZKP;
import result.Worker125Result;
import result.Worker34Result;
import result.Worker6Result;
import utils.Constants;

/**
 * 
 * @author wangnan
 *
 */
public class TestCSS {

	public static void main(String[] args) {

		List<Config> configs = null;

		// users
//		 List<Integer> num_users = Arrays.asList(2, 4, 6, 8, 10, 14, 20);
//		 configs = num_users.stream().map(i -> new Config().withNum_users(i).withDecrypt_num(i / 2)
//				 .withScaling(100).withNum_cores(6)).collect(Collectors.toList());

		// scalings
		//List<Integer> scalings = Arrays.asList(10);
//		 List<Integer> scalings = Arrays.asList(1,3,5,7,10,12,15,18,20);
//		 configs = scalings.stream().map(i -> new Config().withScaling(i)
//				 .withNum_users(20).withDecrypt_num(10).withNum_cores(6)).collect(Collectors.toList());

		// cores
		List<Integer> num_cores = Arrays.asList(6);
		configs = num_cores.stream().map(i -> new Config().withNum_users(20).withDecrypt_num(10).withNum_cores(i)
				.withScaling(100))
				.collect(Collectors.toList());
		
		for (Config config : configs) {
			
			Map<String, List<Double>> times = new HashMap<>();
			times.put(Constants.User_1, Lists.newArrayList());
			times.put(Constants.User_2, Lists.newArrayList());
			times.put(Constants.Operator_1, Lists.newArrayList());
			times.put(Constants.Operator_2, Lists.newArrayList());

			List<Double> errors = Lists.newArrayList();
			
			for (int i = 0; i < 1; i++) {
				test(config, times, errors);
			}
			
			System.out.println("scalings:" + config.getScaling());
			double user_stage_1 = times.get(Constants.User_1).stream().mapToDouble(x -> x.doubleValue()).average().getAsDouble();
			double user_stage_2 = times.get(Constants.User_2).stream().mapToDouble(x -> x.doubleValue()).average().getAsDouble();
			double user_total = user_stage_1 + user_stage_2;

			double operator_stage_1 = times.get(Constants.Operator_1).stream().mapToDouble(x -> x.doubleValue()).average().getAsDouble();
			double operator_stage_2 = times.get(Constants.Operator_2).stream().mapToDouble(x -> x.doubleValue()).average().getAsDouble();
			double operator_total = operator_stage_1 + operator_stage_2;

			System.out.println("User 1:" + times.get(Constants.User_1));
			System.out.println("User 2:" + times.get(Constants.User_2));
			System.out.println("User:" + user_stage_1 + ", " + user_stage_2 + ", " + user_total);
			
			System.out.println("Operator 1:" + times.get(Constants.Operator_1));
			System.out.println("Operator 2:" + times.get(Constants.Operator_2));
			System.out.println("Operator:" + operator_stage_1 + ", " + operator_stage_2 + ", " + operator_total);
			
			double error = errors.stream().mapToDouble(x -> x).average().getAsDouble();
			System.out.println(errors);
			System.out.println("error:" + error);
		}
	}

	public static void test(Config config, Map<String, List<Double>> times, List<Double> errors) {

		int num_cores = config.getNum_cores();

		/**
		 ********************************* Initialization ********************************
		 */
		ExecutorService executor = Executors.newFixedThreadPool(num_cores);

		// initialize keys
		PaillierPrivateThresholdKey[] keys = KeyGen.PaillierThresholdKey(Constants.KEY_BITS_LENGTH,
				config.getNum_users(), config.getDecrypt_num(), new Random().nextLong());

		Paillier paillier = new Paillier(keys[0].getPublicKey());

		// initialize users
		Map<Integer, User> users = initUsers(config.getNum_users(), paillier, keys, config);

		// initialize operator
		Operator operator = new Operator(paillier, config);
		operator.initRandoms();

		/**
		 ******************************** Stage 1 ********************************
		 */
		long o1 = 0;
		long s = System.currentTimeMillis();
		for (int i = 0; i < Constants.NUM_SLOTS; i++) {
			
			boolean userGabageAccumulate = true;
			do {
				// Users -> Operator
				List<BigInteger> ciphers = Lists.newArrayList();
				users.values().forEach(user -> {
					user.CSS_generateGabage();
					ciphers.add(user.CSS_encryptInstantGabage(config.getNum_users()));
				});

				/**
				 * Operator -> User parallel computation divide by users
				 */
				int size = users.size() / config.getNum_cores();
				List<List<BigInteger>> partitions = Lists.partition(ciphers, size == 0 ? 1 : size);
				BigInteger scaledRandom = operator.scale(operator.CSS_generateRandom());
				
				// parallel computation
				List<Future<Worker6Result>> futures = Lists.newArrayList();
				for (List<BigInteger> partition : partitions) {
					futures.add(executor.submit(new Worker6(scaledRandom, partition, operator.getEncrypter())));
				}
				long max = 0;
				List<BigInteger> retList = Lists.newArrayList();
				for (Future<Worker6Result> future : futures) {
					try {
						Worker6Result ret = future.get();
						if(ret.getTime() > max) {
							max = ret.getTime();
						}
						retList.add(ret.getCipher());
					} catch (InterruptedException e1) {
						e1.printStackTrace();
					} catch (ExecutionException e1) {
						e1.printStackTrace();
					}
				}
				
				long s1 = System.nanoTime();
				// merge results
				BigInteger aggregation1 = operator.CSS_aggregateUserCiphers(retList);
				long e1 = System.nanoTime();
				o1 += (e1 - s1 + max);
				
				List<BigInteger> checkVals = Lists.newArrayList();			
				for (User user : users.values()) {
					Set<Integer> userIDs = operator.generateRandomUserIDs(users.size(), config.getDecrypt_num(), user.getId());
					List<DecryptionZKP> shares = userIDs.stream()
							.map(id -> users.get(id).CSS_decryptCipher(aggregation1)).collect(Collectors.toList());
					checkVals.add(user.getStage1Ret(user.CSS_combineAllShares1(shares)));
				}
				
				
				/**
				 * User -> Operator
				 */
				if (checkVals.get(0).compareTo(BigInteger.ZERO) > 0) {
					userGabageAccumulate = false;
				}
			} while (userGabageAccumulate);

			for (User user : users.values()) {
				user.recordInstantGabages();
			}
			//System.out.println("slot:" + i + " " + userGabageAccumulate);
		}
		long e = System.currentTimeMillis();
		long u1 = (long) ((e - s - NanoToMillis(o1)) / users.size());

		times.get(Constants.User_1).add((double) u1);
		times.get(Constants.Operator_1).add(NanoToMillis(o1));


		/**
		 ******************************** stage 2 ********************************
		 */
		/**
		 * Users -> Operator
		 */
		System.out.println("stage 2 begins");
		s = System.currentTimeMillis();
		Map<Integer, List<BigInteger>> gabagesMap = users.values().stream()
				.collect(Collectors.toMap(user -> user.getId(), user -> user.CSS_encryptGabage()));
		e = System.currentTimeMillis();
		long u2 = (e - s) / users.size();

		/**
		 * Operator -> Users
		 */
		// operator cache user ciphers
		
		
		operator.setUserCiphers(gabagesMap);
		List<List<Integer>> slots = getPartitionsBySlots(num_cores);

		// parallel computation
		List<Future<Worker34Result>> futures = Lists.newArrayList();
		for (int i = 0; i < num_cores; i++) {
			futures.add(executor.submit(new Worker4(i, slots.get(i), gabagesMap.values(), operator)));
		}
		List<Worker34Result> retList = Lists.newArrayList();
		long max = 0;
		for (Future<Worker34Result> future : futures) {
			try {
				Worker34Result ret = future.get();
				if(ret.getTime() > max) {
					max = ret.getTime();
				}
				
				retList.add(ret);
			} catch (InterruptedException e1) {
				e1.printStackTrace();
			} catch (ExecutionException e1) {
				e1.printStackTrace();
			}
		}

		// merge results
		s = System.nanoTime();
		Collections.sort(retList);
		List<BigInteger> mergeList = retList.stream().flatMap(w -> w.getList().stream()).collect(Collectors.toList());
		e = System.nanoTime();
		long o2 = (e - s + max);
		
		/**
		 * Users -> Operator
		 */
		s = System.currentTimeMillis();
		Map<Integer, List<BigInteger>> addRandomRetMap = users.values().stream().collect(
				Collectors.toMap(user -> user.getId(), user -> user.CSS_addRandomToCiphersFromOperator(mergeList)));
		e = System.currentTimeMillis();
		long u3 = (e - s) / users.size();

		/**
		 * Operator -> users
		 */
		// parallel computation
		
		List<Future<Worker125Result>> futures2 = Lists.newArrayList();
		for (int i = 0; i < num_cores; i++) {
			futures2.add(executor.submit(new Worker5(i, slots.get(i), addRandomRetMap, operator)));
		}
		List<Worker125Result> retList2 = Lists.newArrayList();
		max = 0;
		for (Future<Worker125Result> future : futures2) {
			try {
				Worker125Result ret = future.get();
				if(ret.getTime() > max) {
					max = ret.getTime();
				}
				
				retList2.add(ret);
			} catch (InterruptedException e1) {
				e1.printStackTrace();
			} catch (ExecutionException e1) {
				e1.printStackTrace();
			}
		}

		// merge resultsgetNum_cores()
		s = System.nanoTime();
		Collections.sort(retList2);
		Map<Integer, List<BigInteger>> mergeMap = new HashMap<>();
		for (int i = 0; i < users.size(); i++) {
			List<BigInteger> list = Lists.newArrayList();
			for (int j = 0; j < retList2.size(); j++) {
				List<BigInteger> partition = retList2.get(j).getMap().get(i);
				list.addAll(partition);
			}
			mergeMap.put(i, list);
		}
		e = System.nanoTime();
		long o3 = (e - s + max);

		/**
		 * Users
		 */
		List<Double> total = Lists.newArrayList();
		for (int i = 0; i < Constants.NUM_SLOTS; i++) {
			double sum = 0;
			for (User user : users.values()) {
				sum += user.getGabages().get(i);
			}
			total.add(sum);
		}

		s = System.currentTimeMillis();
		List<List<Double>> finalRet = Lists.newArrayList();
		for (User user : users.values()) {
			List<BigInteger> ret = mergeMap.get(user.getId());
			Set<Integer> userIDs = operator.generateRandomUserIDs(users.size(), config.getDecrypt_num(), user.getId());
			List<List<DecryptionZKP>> list = Lists.newArrayList();
			for (int i = 0; i < Constants.NUM_SLOTS; i++) {
				BigInteger cipher = ret.get(i);

				List<DecryptionZKP> shares = Lists.newArrayList();
				for (int id : userIDs) {
					shares.add(users.get(id).CSS_decryptCipher(cipher));
				}
				list.add(shares);
			}

			finalRet.add(user.getStage2Ret(user.CSS_combineAllShares2(list)));
		}
		e = System.currentTimeMillis();
		long u4 = (e - s) / users.size();
		
		times.get(Constants.User_2).add((double) (u2 + u3 + u4));
		times.get(Constants.Operator_2).add(NanoToMillis(o2 + o3));
		
		List<Double> measures = Lists.newArrayList();
		for (int i = 0; i < Constants.NUM_SLOTS; i++) {
			double actualSum = 0;
			double expectedSum = 0;
			for (User user : users.values()) {
				double actualP = user.getGabages().get(i) / finalRet.get(user.getId()).get(i);
				double expectedP = user.getGabages().get(i) / total.get(i);
				
				actualSum += actualP;
				expectedSum += expectedP;
			}
			
			measures.add(Math.abs(expectedSum - actualSum) / expectedSum);
		}
		
		errors.add(measures.stream().mapToDouble(x -> x).average().getAsDouble());

		executor.shutdownNow();
	}

	public static Map<Integer, User> initUsers(int num_users, Paillier paillier, PaillierPrivateThresholdKey[] keys,
			Config config) {
		Map<Integer, User> users = new HashMap<>();
		for (int i = 0; i < num_users; i++) {
			users.put(i, new User(i, paillier, keys[i], config));
		}

		return users;
	}

	public static List<List<Integer>> getPartitions(Config config) {
		List<Integer> slots = Lists.newArrayList();
		for (int i = 0; i < config.getNum_users(); i++) {
			slots.add(i);
		}
		return Lists.partition(slots, config.getNum_users() / config.getNum_cores());
	}

	public static List<List<Integer>> getPartitionsBySlots(int num_cores) {
		List<Integer> slots = Lists.newArrayList();
		for (int i = 0; i < Constants.NUM_SLOTS; i++) {
			slots.add(i);
		}
		return Lists.partition(slots, Constants.NUM_SLOTS / num_cores);
	}
	
	public static double NanoToMillis(double t) {
		return t / Constants.NANO_TO_MILLIS;
	}
}
