package agent;

/**
 * 
 * @author wangnan
 *
 */
public class Config {
	
	private int scaling = 100;
	private int num_users = 6;
	private int num_cores = 4;
	private int decrypt_num = num_users / 2;
	
	public Config(){
	}

	public int getScaling() {
		return scaling;
	}

	public Config withScaling(int scaling) {
		this.scaling = scaling;
		return this;
	}

	public int getNum_users() {
		return num_users;
	}

	public Config withNum_users(int num_users) {
		this.num_users = num_users;
		return this;
	}

	public int getNum_cores() {
		return num_cores;
	}

	public Config withNum_cores(int num_cores) {
		this.num_cores = num_cores;
		return this;
	}

	public int getDecrypt_num() {
		return decrypt_num;
	}

	public Config withDecrypt_num(int decrypt_num) {
		this.decrypt_num = decrypt_num;
		return this;
	}
}
