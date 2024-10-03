use anchor_lang::{
    prelude::*,
    solana_program::keccak,
};
use spl_account_compression::{
    Noop,
    program::SplAccountCompression,
    cpi::{
        accounts::{Initialize, Modify, VerifyLeaf},
        init_empty_merkle_tree, verify_leaf, replace_leaf, append,
    },
    wrap_application_data_v1,
};

// Replace with your program ID
declare_id!("PROGRAM_PUBLIC_KEY_GOES_HERE");

/// A program that manages compressed notes using a Merkle tree for efficient storage and verification.
#[program]
pub mod compressed_notes {
    use super::*;

    // Define your program instructions here.

    /// Initializes a new Merkle tree for storing messages.
    ///
    /// This function creates a Merkle tree with the specified maximum depth and buffer size.
    ///
    /// # Arguments
    ///
    /// * `ctx` - The context containing the accounts required for initializing the tree.
    /// * `max_depth` - The maximum depth of the Merkle tree.
    /// * `max_buffer_size` - The maximum buffer size of the Merkle tree.
    pub fn create_messages_tree(
        ctx: Context<MessageAccounts>,
        max_depth: u32,
        max_buffer_size: u32,
    ) -> Result<()> {
        // Tree creation logic here

         // Get the address for the Merkle tree account
         let merkle_tree = ctx.accounts.merkle_tree.key();

         // Define the seeds for PDA signing
         let signers_seeds: &[&[&[u8]]] = &[
             &[
                 merkle_tree.as_ref(), // The address of the Merkle tree account as a seed
                 &[*ctx.bumps.get("tree_authority").unwrap()], // The bump seed for the PDA
             ],
         ];
 
         // Create CPI context for `init_empty_merkle_tree` instruction
         let cpi_ctx = CpiContext::new_with_signer(
             ctx.accounts.compression_program.to_account_info(), // The SPL account compression program
             Initialize {
                 authority: ctx.accounts.tree_authority.to_account_info(), // The authority for the Merkle tree, using a PDA
                 merkle_tree: ctx.accounts.merkle_tree.to_account_info(), // The Merkle tree account to be initialized
                 noop: ctx.accounts.log_wrapper.to_account_info(), // The noop program to log data
             },
             signers_seeds // The seeds for PDA signing
         );
 
         // CPI to initialize an empty Merkle tree with the given max depth and buffer size
         init_empty_merkle_tree(cpi_ctx, max_depth, max_buffer_size)?;

        Ok(())
    }

    /// Appends a new message to the Merkle tree.
    ///
    /// This function hashes the message and adds it as a leaf node to the tree.
    ///
    /// # Arguments
    ///
    /// * `ctx` - The context containing the accounts required for appending the message.
    /// * `message` - The message to append to the Merkle tree.
    pub fn append_message(ctx: Context<MessageAccounts>, message: String) -> Result<()> {
        // Message appending logic here

         // Hash the message + sender's public key to create a leaf node
         let leaf_node = keccak::hashv(&[message.as_bytes(), ctx.accounts.sender.key().as_ref()]).to_bytes();

         // Create a new "MessageLog" using the leaf node hash, sender, recipient, and message
         let message_log = new_message_log(
             leaf_node.clone(),
             ctx.accounts.sender.key().clone(),
             ctx.accounts.recipient.key().clone(),
             message,
         );
 
         // Log the "MessageLog" data using the noop program
         wrap_application_data_v1(message_log.try_to_vec()?, &ctx.accounts.log_wrapper)?;
 
         // Get the Merkle tree account address
         let merkle_tree = ctx.accounts.merkle_tree.key();
 
         // Define the seeds for PDA signing
         let signers_seeds: &[&[&[u8]]] = &[
             &[
                 merkle_tree.as_ref(), // The address of the Merkle tree account as a seed
                 &[*ctx.bumps.get("tree_authority").unwrap()], // The bump seed for the PDA
             ],
         ];
 
         // Create a CPI context and append the leaf node to the Merkle tree
         let cpi_ctx = CpiContext::new_with_signer(
             ctx.accounts.compression_program.to_account_info(), // The SPL account compression program
             Modify {
                 authority: ctx.accounts.tree_authority.to_account_info(), // Authority for the Merkle tree, using a PDA
                 merkle_tree: ctx.accounts.merkle_tree.to_account_info(), // The Merkle tree account to be modified
                 noop: ctx.accounts.log_wrapper.to_account_info(), // The noop program to log data
             },
             signers_seeds, // The seeds for PDA signing
         );
 
         // CPI call to append the leaf node to the Merkle tree
         append(cpi_ctx, leaf_node)?;
 
        Ok(())
    }

    /// Updates an existing message in the Merkle tree.
    ///
    /// This function verifies the old message and replaces it with the new message in the tree.
    ///
    /// # Arguments
    ///
    /// * `ctx` - The context containing the accounts required for updating the message.
    /// * `index` - The index of the message in the tree.
    /// * `root` - The root of the Merkle tree.
    /// * `old_message` - The old message to be replaced.
    /// * `new_message` - The new message to replace the old message.
    pub fn update_message(
        ctx: Context<MessageAccounts>,
        index: u32,
        root: [u8; 32],
        old_message: String,
        new_message: String,
    ) -> Result<()> {
        // Message updating logic here
         // Hash the old message + sender's public key to create the old leaf node
         let old_leaf = keccak::hashv(&[old_message.as_bytes(), ctx.accounts.sender.key().as_ref()]).to_bytes();

         // Get the Merkle tree account address
         let merkle_tree = ctx.accounts.merkle_tree.key();
 
         // Define the seeds for PDA signing
         let signers_seeds: &[&[&[u8]]] = &[
             &[
                 merkle_tree.as_ref(), // The address of the Merkle tree account as a seed
                 &[*ctx.bumps.get("tree_authority").unwrap()], // The bump seed for the PDA
             ],
         ];
 
         // Verify the old leaf node in the Merkle tree
         {
             // If the old and new messages are the same, no update is needed
             if old_message == new_message {
                 msg!("Messages are the same!");
                 return Ok(());
             }
 
             // Create CPI context for verifying the leaf node
             let cpi_ctx = CpiContext::new_with_signer(
                 ctx.accounts.compression_program.to_account_info(), // The SPL account compression program
                 VerifyLeaf {
                     merkle_tree: ctx.accounts.merkle_tree.to_account_info(), // The Merkle tree account to be verified
                 },
                 signers_seeds, // The seeds for PDA signing
             );
 
             // Verify the old leaf node in the Merkle tree
             verify_leaf(cpi_ctx, root, old_leaf, index)?;
         }
 
         // Hash the new message + sender's public key to create the new leaf node
         let new_leaf = keccak::hashv(&[new_message.as_bytes(), ctx.accounts.sender.key().as_ref()]).to_bytes();
 
         // Log the new message for indexers using the noop program
         let message_log = new_message_log(
             new_leaf.clone(),
             ctx.accounts.sender.key().clone(),
             ctx.accounts.recipient.key().clone(),
             new_message,
         );
         wrap_application_data_v1(message_log.try_to_vec()?, &ctx.accounts.log_wrapper)?;
 
         // Replace the old leaf with the new leaf in the Merkle tree
         {
             // Create CPI context for replacing the leaf node
             let cpi_ctx = CpiContext::new_with_signer(
                 ctx.accounts.compression_program.to_account_info(), // The SPL account compression program
                 Modify {
                     authority: ctx.accounts.tree_authority.to_account_info(), // The authority for the Merkle tree, using a PDA
                     merkle_tree: ctx.accounts.merkle_tree.to_account_info(), // The Merkle tree account to be modified
                     noop: ctx.accounts.log_wrapper.to_account_info(), // The noop program to log data
                 },
                 signers_seeds, // The seeds for PDA signing
             );
 
             // Replace the old leaf node with the new one in the Merkle tree
             replace_leaf(cpi_ctx, root, old_leaf, new_leaf, index)?;
         }
 
        Ok(())
    }

    // Add more functions as needed
}


/// Struct for holding the account information required for message operations.
#[derive(Accounts)]
pub struct MessageAccounts<'info> {
    /// The Merkle tree account.
    #[account(mut)]
    pub merkle_tree: AccountInfo<'info>,
    /// The authority for the Merkle tree.
    pub tree_authority: AccountInfo<'info>,
    /// The sender's account.
    pub sender: Signer<'info>,
    /// The recipient's account.
    pub recipient: AccountInfo<'info>,
    /// The compression program (Noop program).
    pub compression_program: Program<'info, SplAccountCompression>,
    /// The log wrapper account for logging data.
    pub log_wrapper: AccountInfo<'info>,
}
#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
/// A struct representing a log entry in the Merkle tree for a note.
pub struct NoteLog {
    /// The leaf node hash generated from the note data.
    pub leaf_node: [u8; 32],
    /// The public key of the note's owner.
    pub owner: Pubkey,
    /// The content of the note.
    pub note: String,
}

/// Constructs a new note log from a given leaf node, owner, and note message.
///
/// # Arguments
///
/// * `leaf_node` - A 32-byte array representing the hash of the note.
/// * `owner` - The public key of the note's owner.
/// * `note` - The note message content.
///
/// # Returns
///
/// A new `NoteLog` struct containing the provided data.
pub fn create_note_log(leaf_node: [u8; 32], owner: Pubkey, note: String) -> NoteLog {
    NoteLog { leaf_node, owner, note }
}

#[derive(Accounts)]
/// Accounts required for interacting with the Merkle tree for note management.
pub struct NoteAccounts<'info> {
    /// The payer for the transaction, who also owns the note.
    #[account(mut)]
    pub owner: Signer<'info>,

    /// The PDA (Program Derived Address) authority for the Merkle tree.
    /// This account is only used for signing and is derived from the Merkle tree address.
    #[account(
        seeds = [merkle_tree.key().as_ref()],
        bump,
    )]
    pub tree_authority: SystemAccount<'info>,

    /// The Merkle tree account, where the notes are stored.
    /// This account is validated by the SPL Account Compression program.
    ///
    /// The `UncheckedAccount` type is used since the account's validation is deferred to the CPI.
    #[account(mut)]
    pub merkle_tree: UncheckedAccount<'info>,

    /// The Noop program used for logging data.
    /// This is part of the SPL Account Compression stack and logs the note operations.
    pub log_wrapper: Program<'info, Noop>,

    /// The SPL Account Compression program used for Merkle tree operations.
    pub compression_program: Program<'info, SplAccountCompression>,
}
#[program]
pub mod compressed_notes {
    use super::*;

    /// Instruction to create a new note tree (Merkle tree) for storing compressed notes.
    ///
    /// # Arguments
    /// * `ctx` - The context that includes the accounts required for this transaction.
    /// * `max_depth` - The maximum depth of the Merkle tree.
    /// * `max_buffer_size` - The maximum buffer size of the Merkle tree.
    ///
    /// # Returns
    /// * `Result<()>` - Returns a success or error result.
    pub fn create_note_tree(
        ctx: Context<NoteAccounts>,
        max_depth: u32,       // Max depth of the Merkle tree
        max_buffer_size: u32, // Max buffer size of the Merkle tree
    ) -> Result<()> {
        // Get the address for the Merkle tree account
        let merkle_tree = ctx.accounts.merkle_tree.key();

        // The seeds for PDAs signing
        let signers_seeds: &[&[&[u8]]] = &[&[
            merkle_tree.as_ref(), // The Merkle tree account address as the seed
            &[*ctx.bumps.get("tree_authority").unwrap()], // The bump seed for the tree authority PDA
        ]];

        // Create a CPI (Cross-Program Invocation) context for initializing the empty Merkle tree.
        let cpi_ctx = CpiContext::new_with_signer(
            ctx.accounts.compression_program.to_account_info(), // The SPL Account Compression program
            Initialize {
                authority: ctx.accounts.tree_authority.to_account_info(), // PDA authority for the Merkle tree
                merkle_tree: ctx.accounts.merkle_tree.to_account_info(),  // The Merkle tree account
                noop: ctx.accounts.log_wrapper.to_account_info(),        // The Noop program for logging data
            },
            signers_seeds, // The seeds for PDAs signing
        );

        // CPI call to initialize an empty Merkle tree with the specified depth and buffer size.
        init_empty_merkle_tree(cpi_ctx, max_depth, max_buffer_size)?;

        Ok(())
    }

    // Additional functions for the program can go here...
}
