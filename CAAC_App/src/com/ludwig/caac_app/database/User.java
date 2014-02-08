package com.ludwig.caac_app.database;

public class User {

	// private variables
	int id;
	String name;
	String email;
	String password;
	int imei;
	int idcounter = 0;
	
	// empty constructor
	public User () {
		
	}
	
	// constructor
	public User (int UserID, String UserName, String UserEmail, String UserPassword, int UserIMEI){
		this.id = UserID;
		this.name = UserName;
		this.email = UserEmail;
		this.password = UserPassword;
		this.imei = UserIMEI;
	}
	
	// constructor
	public User (String UserEmail, String UserPassword){
		this.id = idcounter++;
		this.name = "null";
		this.email = UserEmail;
		this.password = UserPassword;
		this.imei = 0000;
	}
	
	// getting ID
	public int getID(){
		return this.id;
	}
	
	//setting ID
	public void setID(int UserID){
		this.id = UserID;
	}
	
	// getting name
	public String getName(){
		return this.name;
	}
	
	// setting name
	public void setName(String UserName){
		this.name = UserName;
	}
	
	// getting password
	public String getPassword(){
		return this.password;
	}
	
	// setting password
	public void setPassword(String UserPassword){
		this.password = UserPassword;
	}
	
	// getting email
	public String getEmail(){
		return this.email;
	}
	
	// setting email
	public void setEmail(String UserEmail){
		this.email = UserEmail;
	}
	
	// getting IMEI
	public int getIMEI(){
		return this.imei;
	}
	
	// setting IMEI
	public void setIMEI(int UserIMEI){
		this.imei = UserIMEI;
	}
}
