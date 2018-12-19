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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.opencsv.CSVReader;
import com.opencsv.bean.CsvToBean;
import com.opencsv.bean.HeaderColumnNameTranslateMappingStrategy;
import com.thortech.xl.crypto.tcCryptoException;
import com.wiley.bir.domain.UserAttributes;
import com.wiley.bir.exception.EncryptionException;
import com.wiley.bir.util.DecryptPassword;
import com.wiley.bir.util.EncryptionUtil;

public class PasswordService {

	private static final String CSV_SEPARATOR = ",";

	private static final Logger logger = LoggerFactory.getLogger(PasswordService.class);

	public static void generateCSV(String[] args) {
		List<UserAttributes> userAttributes;
		try {
			userAttributes = getUserAttributesFromCSV(args[0]);
			userAttributes = getUsersWithEncryptedPassword(userAttributes);
			writeToCSV(userAttributes, args[0]);
		} catch (Exception e) {
			logger.info("Error occured " + e.getMessage());
		}

	}

	public static List<UserAttributes> getUsersWithEncryptedPassword(List<UserAttributes> userAtributes)
			throws Exception {

		String encryptionKey = "KWhk7PgruBG9DsZV";
		EncryptionUtil encryptionUtil = new EncryptionUtil(encryptionKey);
		logger.debug("IV used for  encryption {}", encryptionUtil.IV);
		logger.debug("Salt used for  encryption  {}", encryptionUtil.ENCRYPTION_KEY_SALT);
		logger.debug("encryption key used for  encryption {} ", encryptionKey);

		
		String encriptedPassword = null;
		DecryptPassword decryptPassword = new DecryptPassword();
		String decryptedOIMPassword = null;
		for (UserAttributes user : userAtributes) {

			try {
				logger.info("OIM Password decryption started for user "+
						user.getUsername() );
				decryptedOIMPassword = decryptPassword.decrypt(user.getPassword());
				logger.info("OIM Password decryption completed for user "+
						user.getUsername() );
				logger.info("Password encryption started for user "+ user.getUsername());
				encriptedPassword = encryptionUtil.encrypt(decryptedOIMPassword);
				user.setPassword(encriptedPassword);
				logger.info("Password encryption completed for user "+ user.getUsername());
			} catch (tcCryptoException e) {
				logger.info("Error wile decrypting OIM password for {}", user.getUsername());
			} catch (EncryptionException e) {
				logger.info("Error wile Encripting password for {}", user.getUsername());
			}catch (Exception e) {
				logger.info("Error occured " + e.getMessage());
			}
			

		}

		logger.info("Decription and encryption completed.");
		return userAtributes;

	}

	public static List<UserAttributes> getUserAttributesFromCSV(String path) throws Exception {
		List<UserAttributes> userAttributes = null;
		try {
			CSVReader csvReader = new CSVReader(new InputStreamReader(new FileInputStream(path)));
			userAttributes = parseCSVToBeanList(csvReader);

		} catch (FileNotFoundException e) {
			logger.info("Invalid path specified for input CSV ...Aborting");
			throw new Exception("Invalid path specified for input CSV ...Aborting");
		} catch (IOException e) {
		}

		return userAttributes;
	}

	private static List<UserAttributes> parseCSVToBeanList(CSVReader csvReader) throws Exception {

		HeaderColumnNameTranslateMappingStrategy<UserAttributes> beanStrategy = new HeaderColumnNameTranslateMappingStrategy<UserAttributes>();
		beanStrategy.setType(UserAttributes.class);

		Map<String, String> columnMapping = new HashMap<String, String>();
		columnMapping.put("USR_UDF_EXTERNALID", "externalId");
		columnMapping.put("USR_LOGIN", "userName");
		columnMapping.put("USR_PASSWORD", "password");

		beanStrategy.setColumnMapping(columnMapping);
		CsvToBean<UserAttributes> csvToBean = new CsvToBean<UserAttributes>();
		try {
			List<UserAttributes> userObjects = csvToBean.parse(beanStrategy, csvReader);
			logger.info("CSV extracted successfully....");
			return userObjects;
		} catch (Exception e) {
			logger.error("Error while extracting CSV.....Check the CSV format");
			throw new Exception("Error while extracting CSV.....Check the CSV format");
		}

	}

	private static void writeToCSV(List<UserAttributes> userAttributes, String path) {
		String[] paths = path.split("custPassword.csv");

		String outputpath = paths[0] + "librarianPasswords.csv";
		try {
			BufferedWriter bw = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(outputpath), "UTF-8"));
			StringBuffer oneLine = new StringBuffer();
			oneLine.append("\"EXTERNALID\",\"USERNAME\",\"PASSWORD\"");
			bw.write(oneLine.toString());
			bw.newLine();

			for (UserAttributes user : userAttributes) {
				oneLine = new StringBuffer();
				oneLine.append(user.getExternalId().trim().length() == 0 ? "" : "\"" + user.getExternalId() + "\"");
				oneLine.append(CSV_SEPARATOR);
				oneLine.append(user.getUsername().trim().length() == 0 ? "" : "\"" + user.getUsername() + "\"");
				oneLine.append(CSV_SEPARATOR);
				oneLine.append(user.getPassword().trim().length() == 0 ? "" : "\"" + user.getPassword() + "\"");
				bw.write(oneLine.toString());
				bw.newLine();
			}
			bw.flush();
			bw.close();
			logger.info("Output CSV created successfully in {}", outputpath);
		} catch (Exception e) {
			logger.error("Error while creating  CSV.");
		}
	}

}
