package result;

import java.math.BigInteger;
import java.util.List;
import java.util.Map;

/**
 * 
 * @author wangnan
 *
 */
public class Worker125Result implements Comparable<Worker125Result> {
	
	private final int id;
	private final Map<Integer, List<BigInteger>> map;
	private long time;
	
	public Worker125Result(int id, Map<Integer, List<BigInteger>> map, long time){
		this.id = id;
		this.map = map;
		this.time = time;
	}

	public int getId() {
		return id;
	}

	public Map<Integer, List<BigInteger>> getMap() {
		return map;
	}

	public long getTime() {
		return time;
	}

	public void setTime(long time) {
		this.time = time;
	}

	@Override
	public int compareTo(Worker125Result o) {
		return this.id - o.getId();
	}
}
