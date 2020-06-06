package stage_threshold;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
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
import agent.Worker1;
import agent.Worker2;
import agent.Worker3;
import paillierp.Paillier;
import paillierp.key.KeyGen;
import paillierp.key.PaillierPrivateThresholdKey;
import paillierp.zkp.DecryptionZKP;
import result.Worker125Result;
import result.Worker34Result;
import utils.Constants;

/**
 * 
 * @author wangnan
 *
 */
public class TestUFS {

	public static void main(String[] args) {

		List<Config> configs = null;

		// users
//		 List<Integer> num_users = Arrays.asList(2, 4, 6, 8, 10, 14, 20);
//		 configs = num_users.stream().map(i -> new Config().withNum_users(i).withDecrypt_num(i / 2)
//				 .withScaling(1).withNum_cores(6)).collect(Collectors.toList());

		// scalings
//		 List<Integer> scalings = Arrays.asList(18);
//		 configs = scalings.stream().map(i -> new Config().withScaling(i)
//				 .withNum_users(20).withDecrypt_num(10).withNum_cores(6)).collect(Collectors.toList());

		// cores
		List<Integer> num_cores = Arrays.asList(1, 2, 4, 6);
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
			
			for (int i = 0; i < 20; i++) {
				test(config, times, errors);
			}
			
			System.out.println("Cores:" + config.getNum_cores());
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
			
//			double error = errors.stream().mapToDouble(x -> x).average().getAsDouble();
//			System.out.println(errors);
//			System.out.println("error:" + error);
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
		Map<Integer, User> users = initUsers(paillier, keys, config);

		// initialize operator
		Operator operator = new Operator(paillier, config);

		/**
		 ********************************* Stage 1 ********************************
		 */
		/**
		 * Users -> Operator
		 */
		long s = System.currentTimeMillis();
		Map<Integer, List<BigInteger>> ciphersMap = users.values().stream()
				.collect(Collectors.toMap(user -> user.getId(), user -> user.UFS_encryptOccupancies()));
		long e = System.currentTimeMillis();
		long u1 = (e - s) / users.size();

		/**
		 * Operator -> Users;
		 */
		// store user info locally
		operator.cacheUserInfo(ciphersMap);
		List<List<Integer>> partitions = getPartitions(num_cores);
		// parallel computation
		List<Future<Worker125Result>> futures = Lists.newArrayList();
		for (int i = 0; i < num_cores; i++) {
			futures.add(executor.submit(new Worker1(i, partitions.get(i), operator)));
		}
		
		long max = 0;
		List<Worker125Result> retList = Lists.newArrayList();
		for (Future<Worker125Result> future : futures) {
			try {
				Worker125Result ret = future.get();
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
		
		s = System.nanoTime();
		// merge results
		Collections.sort(retList);
		Map<Integer, List<BigInteger>> mergeMap = new HashMap<>();
		for (User user : users.values()) {
			List<BigInteger> list = Lists.newArrayList();
			for (int j = 0; j < retList.size(); j++) {
				List<BigInteger> partition = retList.get(j).getMap().get(user.getId());
				list.addAll(partition);
			}
			mergeMap.put(user.getId(), list);
		}
		e = System.nanoTime();
		long o1 = (e - s + max);

		// compare the two result
		Map<Integer, List<BigInteger>> actualOccupancyMap = getExpectedTotal(users);

		/**
		 * Users -> Operator
		 */
		long o2 = 0;
		long s1 = System.currentTimeMillis();
		Map<Integer, List<BigInteger>> expectedOccupancyMap = new HashMap<>();
		for (User user : users.values()) {
			// get the computed cipher for this user
			List<BigInteger> ciphers = mergeMap.get(user.getId());

			s = System.nanoTime();
			// should not include user himself
			Set<Integer> userIDs = operator.generateRandomUserIDs(users.size(), config.getDecrypt_num(), user.getId());
			e = System.nanoTime();
			o2 += (e - s);

			List<List<DecryptionZKP>> sharesList = Lists.newArrayList();

			for (BigInteger cipher : ciphers) {
				List<DecryptionZKP> shares = userIDs.stream().map(id -> users.get(id).UFS_decryptOccupancyShare(cipher))
						.collect(Collectors.toList());
				sharesList.add(shares);
			}

			List<BigInteger> expectedOccupancies = user.UFS_combineOccupancyShares(sharesList);
			expectedOccupancyMap.put(user.getId(), expectedOccupancies);
		}
		long e1 = System.currentTimeMillis();
		long u2 = (long) ((e1 - s1 - NanoToMillis(o2)) / users.size());

		System.out.println(compareMap(actualOccupancyMap, expectedOccupancyMap) ? "SUCCESS" : "FAILURE");

		times.get(Constants.User_1).add((double) (u1 + u2));
		times.get(Constants.Operator_1).add(NanoToMillis(o1 + o2));

		/**
		 ********************************* Stage 2 ********************************
		 */
		/**
		 * Operator -> Users Generate a random number for each slot and user
		 */
		List<Future<Worker125Result>> futures2 = new ArrayList<>();
		for (int i = 0; i < num_cores; i++) {
			futures2.add(executor.submit(new Worker2(i, num_cores, operator.getUsers().values())));
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
			} catch (InterruptedException ex) {
				ex.printStackTrace();
			} catch (ExecutionException ex) {
				ex.printStackTrace();
			}
		}
		
		s = System.nanoTime();
		// merge results
		Collections.sort(retList2);
		Map<Integer, List<BigInteger>> randomMap = new HashMap<>();
		for (int i = 0; i < users.size(); i++) {
			List<BigInteger> list = Lists.newArrayList();
			for (int j = 0; j < retList2.size(); j++) {
				List<BigInteger> partition = retList2.get(j).getMap().get(i);
				list.addAll(partition);
			}
			randomMap.put(i, list);
		}
		operator.cacheUserRandoms(randomMap);
		e = System.nanoTime();
		long o3 = e - s + max;

		/**
		 * Users -> Operator
		 */
		s = System.currentTimeMillis();
		Map<Integer, List<BigInteger>> coarseOccupancyMap = new HashMap<>();
		for (User user : users.values()) {
			List<BigInteger> randoms = randomMap.get(user.getId());
			coarseOccupancyMap.put(user.getId(), user.UFS_encryptCoarseOccupancies(randoms));
		}
		e = System.currentTimeMillis();
		long u3 = (e - s) / users.size();

		/**
		 * Operator -> Users
		 */
		
		// parallel computation
		List<Future<Worker34Result>> futures3 = new ArrayList<>();
		for (int i = 0; i < num_cores; i++) {
			futures3.add(executor
					.submit(new Worker3(i, partitions.get(i), coarseOccupancyMap.values(), operator.getEncrypter())));
		}
		List<Worker34Result> retList3 = Lists.newArrayList();
		max = 0;
		for (Future<Worker34Result> future : futures3) {
			try {
				Worker34Result ret = future.get();
				if(ret.getTime() > max) {
					max = ret.getTime();
				}
				retList3.add(ret);
			} catch (InterruptedException ex) {
				ex.printStackTrace();
			} catch (ExecutionException ex) {
				ex.printStackTrace();
			}
		}
		
		s = System.nanoTime();
		// merge results
		Collections.sort(retList3);
		List<BigInteger> mergeList = retList3.stream().flatMap(w -> w.getList().stream()).collect(Collectors.toList());
		e = System.nanoTime();
		long o4 = e - s + max;

		/**
		 * Users -> Operator
		 */
		s = System.currentTimeMillis();
		List<List<BigInteger>> actualCoarseOccupancis = Lists.newArrayList();
		for (User user : users.values()) {
			Set<Integer> userIDs = operator.generateRandomUserIDs(users.size(), config.getDecrypt_num(), user.getId());

			List<List<DecryptionZKP>> shares = userIDs.stream()
					.map(id -> users.get(id).UFS_decryptCoarseOccupancyShare(mergeList)).collect(Collectors.toList());

			List<BigInteger> eachOccupancy = user.UFS_combineCoarseOccupancyShares(shares);
			actualCoarseOccupancis.add(eachOccupancy);
		}
		e = System.currentTimeMillis();
		long u4 = (e - s) / users.size();

		/**
		 * Operator
		 */
		s = System.nanoTime();
		List<BigInteger> actualCoarseOccupancy = operator.UFS_getCoarseOccupancies(actualCoarseOccupancis.get(0));
		e = System.nanoTime();
		long o5 = e - s;

		System.out.println("actual:" + actualCoarseOccupancy);
		List<BigInteger> expectedCoarseOccupancy = getExpectedCoarseOccupancies(users);

		double expectedSum = expectedCoarseOccupancy.stream().mapToDouble(x -> x.doubleValue()).sum();
		double actualSum = actualCoarseOccupancy.stream().mapToDouble(x -> x.doubleValue()).sum();

		errors.add(Math.abs(expectedSum - actualSum) / expectedSum);	

		times.get(Constants.User_2).add((double) (u3 + u4));
		times.get(Constants.Operator_2).add(NanoToMillis(o3 + o4 + o5));

		executor.shutdownNow();
	}

	public static Map<Integer, List<BigInteger>> getExpectedTotal(Map<Integer, User> users) {

		List<BigInteger> total = Lists.newArrayList();
		for (int i = 0; i < Constants.NUM_SLOTS; i++) {
			int sum = 0;
			for (User user : users.values()) {
				sum += user.getOccupancies().get(i).intValue();
			}
			total.add(BigInteger.valueOf(sum));
		}

		Map<Integer, List<BigInteger>> expectedMap = new HashMap<>();
		for (User user : users.values()) {
			List<BigInteger> con = Lists.newArrayList();
			con.addAll(total);
			for (int i = 0; i < Constants.NUM_SLOTS; i++) {
				if (user.getOccupancies().get(i).intValue() == 0) {
					con.set(i, BigInteger.ZERO);
				}
			}

			expectedMap.put(user.getId(), con);
		}

		return expectedMap;
	}

	public static List<BigInteger> getExpectedCoarseOccupancies(Map<Integer, User> users) {
		List<BigInteger> occupancies = Lists.newArrayList();
		for (int i = 0; i < Constants.NUM_SLOTS; i++) {
			occupancies.add(BigInteger.ZERO);
			for (User user : users.values()) {
				if (user.getOccupancies().get(i).intValue() == 1) {
					occupancies.set(i, BigInteger.ONE);
					break;
				}
			}
		}

		return occupancies;
	}

	public static boolean compareMap(Map<Integer, List<BigInteger>> map1, Map<Integer, List<BigInteger>> map2) {
		for (Entry<Integer, List<BigInteger>> entry : map1.entrySet()) {

			List<BigInteger> concurrent = entry.getValue();
			List<BigInteger> concurrent2 = map2.get(entry.getKey());

			for (int i = 0; i < Constants.NUM_SLOTS; i++) {
				if (concurrent.get(i).compareTo(concurrent2.get(i)) != 0) {
					System.out.println(concurrent);
					System.out.println(concurrent2);
					return false;
				}
			}
		}

		return true;
	}

	public static boolean compareArray(List<BigInteger> actual, List<BigInteger> expected) {
		for (int i = 0; i < actual.size(); i++) {
			if (expected.get(i).compareTo(actual.get(i)) != 0) {
				return false;
			}
		}

		return true;
	}

	public static Map<Integer, User> initUsers(Paillier paillier, PaillierPrivateThresholdKey[] keys, Config config) {
		Map<Integer, User> users = new HashMap<>();
		for (int i = 0; i < config.getNum_users(); i++) {
			User user = new User(i, paillier, keys[i], config);
			user.initOccupancies();
			users.put(i, user);
		}

		return users;
	}

	public static List<List<Integer>> getPartitions(int num_cores) {
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
