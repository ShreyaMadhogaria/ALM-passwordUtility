package com.wiley.bir.service;

import java.io.BufferedWriter;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.opencsv.CSVReader;
import com.opencsv.bean.CsvToBean;
import com.opencsv.bean.HeaderColumnNameTranslateMappingStrategy;
import com.wiley.bir.domain.UserAttributes;
import com.wiley.bir.util.DecryptPassword;
import com.wiley.bir.util.EncryptionUtil;

public class PasswordService {
	
	private static final String CSV_SEPARATOR = ",";
	
	/*public static void main(String[] args) {
		List<UserAttributes> userAttributes=getUserAttributesFromCSV(args.toString());
        userAttributes=getUsersWithEncryptedPassword(userAttributes);
		writeToCSV(userAttributes);
	}*/
	
	public static void generateCSV(String[] args) {
		List<UserAttributes> userAttributes=getUserAttributesFromCSV(args[0]);
        userAttributes=getUsersWithEncryptedPassword(userAttributes);
		writeToCSV(userAttributes);
	}
	 
	public static List<UserAttributes> getUsersWithEncryptedPassword(List<UserAttributes> userAtributes){
		try {
			EncryptionUtil encryptionUtil=new EncryptionUtil("wileystandard");
			DecryptPassword decryptPassword=new DecryptPassword();
			for(UserAttributes user:userAtributes) {
				String decryptedOIMPassword=decryptPassword.decrypt(user.getPassword());
				user.setPassword(encryptionUtil.encrypt(decryptedOIMPassword));
			}
			
		} catch (Exception e) {
		}
		
		return userAtributes;
		
	}
	
	
	public static  List<UserAttributes> getUserAttributesFromCSV(String path){
		List<UserAttributes> userAttributes=null;
		try {
			CSVReader csvReader = new CSVReader(new InputStreamReader(new FileInputStream(path)));
			 userAttributes=parseCSVToBeanList(csvReader);
			 
		} catch (FileNotFoundException e) {
		}
		catch (IOException e) {
		}
		
		return userAttributes;
	}
	
	private static List<UserAttributes> parseCSVToBeanList(CSVReader csvReader) throws IOException {

		HeaderColumnNameTranslateMappingStrategy<UserAttributes> beanStrategy = new HeaderColumnNameTranslateMappingStrategy<UserAttributes>();
		beanStrategy.setType(UserAttributes.class);

		Map<String, String> columnMapping = new HashMap<String, String>();
		columnMapping.put("USR_UDF_EXTERNALID", "externalId");
		columnMapping.put("USR_LOGIN", "userName");
		columnMapping.put("USR_PASSWORD", "password");
		

		beanStrategy.setColumnMapping(columnMapping);
		CsvToBean<UserAttributes> csvToBean = new CsvToBean<UserAttributes>();
		List<UserAttributes> userObjects = csvToBean.parse(beanStrategy, csvReader);
		return userObjects;
	}

	 
	    private static void writeToCSV(List<UserAttributes> userAttributes)
	    {
	    	
	        try
	        {
	            BufferedWriter bw = new BufferedWriter(new OutputStreamWriter(new FileOutputStream("output.csv"), "UTF-8"));
	            StringBuffer oneLine = new StringBuffer();
                oneLine.append("USR_UDF_EXTERNALID,USR_LOGIN,USR_PASSWORD");
                bw.write(oneLine.toString());
               	bw.newLine();
               	
	            for (UserAttributes user : userAttributes)
	            {
	            	oneLine = new StringBuffer();
	                oneLine.append(user.getExternalId().trim().length() == 0? "" :user.getExternalId());
	                oneLine.append(CSV_SEPARATOR);
	                oneLine.append(user.getUsername().trim().length() == 0? "" :user.getUsername());
	                oneLine.append(CSV_SEPARATOR);
	                oneLine.append(user.getPassword().trim().length() == 0? "" :user.getPassword());             
	                bw.write(oneLine.toString());
	                bw.newLine();
	            }
	            bw.flush();
	            bw.close();
	        }
	        catch (UnsupportedEncodingException e) {}
	        catch (FileNotFoundException e){}
	        catch (IOException e){}
	    }
	
}
