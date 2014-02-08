package com.ludwig.caac_app.database;

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;

public class DatabaseHandler extends SQLiteOpenHelper{

	// all static variables
	// database version
	private static final int DATABASE_VERSION = 1;
	
	// database name
	private static final String DATABASE_NAME = "usersManager";
	
	// users table name
	private static final String TABLE_USERS = "users";
	
	// users table columns names
	private static final String KEY_ID = "id";
	private static final String KEY_NAME = "name";
	private static final String KEY_EMAIL = "email";
	private static final String KEY_PASSWORD = "password";
	private static final String KEY_IMEI = "imei";
	
	public DatabaseHandler(Context context){
		super(context, DATABASE_NAME, null, DATABASE_VERSION);
	}
	
	// creating tables
	@Override
	public void onCreate(SQLiteDatabase db){
		String CREATE_USERS_TABLE = "CREATE TABLE " + TABLE_USERS + "("
				+ KEY_ID + " INTEGER PRIMARY KEY," + KEY_NAME + " TEXT,"
				+ KEY_EMAIL + " TEXT," + KEY_PASSWORD + " TEXT," + KEY_IMEI + " INTEGER" + ")";
		db.execSQL(CREATE_USERS_TABLE);
	}

	// upgrading database
	@Override
	public void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion){
		// drop older tables if they exist
		db.execSQL("DROP TABLE IF EXIST " + TABLE_USERS);
		
		// create tables again
		onCreate(db);
	}
	
	/**
	 * CRUD operations
	 */
	
	// adding new user
	public void addUser(User user){
		SQLiteDatabase db = this.getWritableDatabase();
		
		ContentValues values = new ContentValues();
		values.put(KEY_NAME, user.getPassword());
		values.put(KEY_EMAIL, user.getEmail());
		values.put(KEY_PASSWORD, user.getPassword());
		values.put(KEY_IMEI, user.getIMEI());
		
		db.insert(TABLE_USERS, null, values);
		db.close();
	}
	
	// getting a single user via ID
	public User getUserByID(int id){
		SQLiteDatabase db = this.getReadableDatabase();

		Cursor cursor = db.query(TABLE_USERS, new String[]{KEY_ID,  KEY_NAME,
				KEY_EMAIL, KEY_PASSWORD, KEY_IMEI}, KEY_ID + "=?", new String []{String.valueOf(id)},
				null, null, null, null);
		if(cursor != null)
			cursor.moveToFirst();

		User user = new User(Integer.parseInt(cursor.getString(0)), cursor.getString(1),
				cursor.getString(2), cursor.getString(3), Integer.parseInt(cursor.getString(4)));
		
		return user;
	}
	
	// getting single user via email
	public User getUserByEmail(String email){
		SQLiteDatabase db = this.getReadableDatabase();

		Cursor cursor = db.query(TABLE_USERS, new String[]{KEY_ID,  KEY_NAME,
				KEY_EMAIL, KEY_PASSWORD, KEY_IMEI}, KEY_EMAIL + "=?", new String []{email},
				null, null, null, null);
		if(cursor != null)
			cursor.moveToFirst();

		User user = new User(Integer.parseInt(cursor.getString(0)), cursor.getString(1),
				cursor.getString(2), cursor.getString(3), Integer.parseInt(cursor.getString(4)));
		return user;
	}
		
	// check if user is in database
	public Boolean tableContainsUser(String email){
		SQLiteDatabase db = this.getReadableDatabase();
		
		Cursor cursor = db.query(TABLE_USERS, new String[]{KEY_ID, KEY_NAME,
				KEY_EMAIL, KEY_PASSWORD, KEY_IMEI}, KEY_EMAIL + "=?", new String[]{email},
				null, null, null, null);

		if(cursor.moveToFirst()){
			return true;
		} else {
			return false;	
		}	
	}
	
	// update a single user
	public int updateUser(User user){
		SQLiteDatabase db = this.getWritableDatabase();
		
		ContentValues values = new ContentValues();
		values.put(KEY_NAME, user.getName());
		values.put(KEY_EMAIL, user.getEmail());
		values.put(KEY_PASSWORD, user.getPassword());
		values.put(KEY_IMEI, user.getIMEI());
		
		// update row
		return db.update(TABLE_USERS, values, KEY_ID + " = ?", new String [] {
				String.valueOf(user.getID())});	
	}
	
	// delete single user
	public void deleteUser(User user){
		SQLiteDatabase db = this.getWritableDatabase();
		db.delete(TABLE_USERS, KEY_ID + " = ?", new String[] 
				{String.valueOf(user.getID())});
	}
}
