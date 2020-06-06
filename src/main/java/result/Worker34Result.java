package result;

import java.math.BigInteger;
import java.util.List;

/**
 * 
 * @author wangnan
 *
 */
public class Worker34Result implements Comparable<Worker34Result> {

	private final int id;
	private final List<BigInteger> list;
	private final long time;

	public Worker34Result(int id, List<BigInteger> list, long time) {
		this.id = id;
		this.list = list;
		this.time = time;
	}

	public int getId() {
		return id;
	}

	public List<BigInteger> getList() {
		return list;
	}

	public long getTime() {
		return time;
	}

	@Override
	public int compareTo(Worker34Result o) {
		return this.id - o.getId();
	}
}
