package com.ludwig.caac_app;

import android.app.AlertDialog;
import android.app.Dialog;
import android.content.DialogInterface;
import android.os.Bundle;
import android.support.v4.app.DialogFragment;
import android.view.LayoutInflater;
import android.view.View;
import android.widget.EditText;

public class VerificationDialogFragment extends DialogFragment {
    
	public interface DialogReturn {
		void onDialogCompleted(boolean answer);
	}
	
    private Boolean correctCode = false;
    
	@Override
	public Dialog onCreateDialog(Bundle savedInstanceState) {
		// use builder for easy dialog construction
		AlertDialog.Builder verification = new AlertDialog.Builder(getActivity());
		// get layout inflater
		LayoutInflater inflater = getActivity().getLayoutInflater();
		
		// inflate and set layout for the dialog and add action buttons
		final View view = inflater.inflate(R.layout.activity_verification_dialog, null);
		verification.setView(view)
			.setPositiveButton(R.string.confirm, new DialogInterface.OnClickListener() {
				
				@Override
				public void onClick(DialogInterface dialog, int id) {
					EditText mText = (EditText) view.findViewById(R.id.verificationText);
		            mText.getText().toString();
		            if (mText.equals("0000")){
		            	correctCode = true;
		            	VerificationDialogFragment.this.getDialog().dismiss();
		            }
		            else{
		            	correctCode = false;
		            	VerificationDialogFragment.this.getDialog().cancel();
		            }	
				}
			})
			.setNegativeButton(R.string.cancel, new DialogInterface.OnClickListener() {
				
				@Override
				public void onClick(DialogInterface dialog, int id) {
					VerificationDialogFragment.this.getDialog().cancel();
					
				}
			});
		return verification.create();
	}	
}
