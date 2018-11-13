package com.wiley.bir;

import com.wiley.bir.service.PasswordService;


public class BirApplication {

	public static void main(String[] args) {
		BirApplication birApplication=new BirApplication();
		birApplication.run(args);
	}


	public void run(String... args) {
		PasswordService passwordService=new PasswordService();
		passwordService.generateCSV(args);
		
	}
	
	
}
