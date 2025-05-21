// tests/unit/secure_channel_test.rs
use pali_coin::secure_channel::{SecureChannelManager, EncryptedMessage};
use std::net::{SocketAddr, IpAddr, Ipv4Addr};
use std::collections::HashSet;
use rand::{Rng, rngs::OsRng};

#[test]
fn test_secure_channel_establishment() {
    // Create two secure channel managers
    let manager1 = SecureChannelManager::new();
    let manager2 = SecureChannelManager::new();
    
    // Get their public keys
    let pubkey1 = manager1.get_public_key();
    let pubkey2 = manager2.get_public_key();
    
    // Create test addresses
    let addr1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8001);
    let addr2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8002);
    
    // Establish secure channels
    let result1 = manager1.establish_channel(&pubkey2, addr2);
    let result2 = manager2.establish_channel(&pubkey1, addr1);
    
    // Verify establishment was successful
    assert!(result1.is_ok(), "Failed to establish channel 1->2");
    assert!(result2.is_ok(), "Failed to establish channel 2->1");
}

#[test]
fn test_message_encryption_decryption() {
    // Create two secure channel managers
    let manager1 = SecureChannelManager::new();
    let manager2 = SecureChannelManager::new();
    
    // Get their public keys
    let pubkey1 = manager1.get_public_key();
    let pubkey2 = manager2.get_public_key();
    
    // Create test addresses
    let addr1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8001);
    let addr2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8002);
    
    // Establish secure channels
    manager1.establish_channel(&pubkey2, addr2).expect("Failed to establish channel 1->2");
    manager2.establish_channel(&pubkey1, addr1).expect("Failed to establish channel 2->1");
    
    // Test message encryption and decryption
    let test_message = b"Secure test message for Pali Coin";
    
    // Encrypt from manager1 to manager2
    let encrypted = manager1.encrypt_message(addr2, test_message)
        .expect("Failed to encrypt message");
    
    // Decrypt at manager2
    let decrypted = manager2.decrypt_message(addr1, &encrypted)
        .expect("Failed to decrypt message");
    
    // Verify decryption
    assert_eq!(test_message.to_vec(), decrypted, "Decrypted message doesn't match original");
}

#[test]
fn test_replay_attack_prevention() {
    // Create two secure channel managers
    let manager1 = SecureChannelManager::new();
    let manager2 = SecureChannelManager::new();
    
    // Get their public keys
    let pubkey1 = manager1.get_public_key();
    let pubkey2 = manager2.get_public_key();
    
    // Create test addresses
    let addr1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8001);
    let addr2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8002);
    
    // Establish secure channels
    manager1.establish_channel(&pubkey2, addr2).expect("Failed to establish channel 1->2");
    manager2.establish_channel(&pubkey1, addr1).expect("Failed to establish channel 2->1");
    
    // Test message encryption and decryption
    let test_message = b"Test message for replay attack prevention";
    
    // Encrypt from manager1 to manager2
    let encrypted = manager1.encrypt_message(addr2, test_message)
        .expect("Failed to encrypt message");
    
    // Decrypt at manager2 (should succeed)
    let decrypted = manager2.decrypt_message(addr1, &encrypted)
        .expect("Failed to decrypt message");
    assert_eq!(test_message.to_vec(), decrypted);
    
    // Try to replay the same message (should fail)
    let replay_result = manager2.decrypt_message(addr1, &encrypted);
    assert!(replay_result.is_err(), "Replay attack prevention failed");
}

#[test]
fn test_multiple_message_exchange() {
    // Create two secure channel managers
    let manager1 = SecureChannelManager::new();
    let manager2 = SecureChannelManager::new();
    
    // Get their public keys
    let pubkey1 = manager1.get_public_key();
    let pubkey2 = manager2.get_public_key();
    
    // Create test addresses
    let addr1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8001);
    let addr2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8002);
    
    // Establish secure channels
    manager1.establish_channel(&pubkey2, addr2).expect("Failed to establish channel 1->2");
    manager2.establish_channel(&pubkey1, addr1).expect("Failed to establish channel 2->1");
    
    // Exchange multiple messages in both directions
    for i in 1..10 {
        // Manager1 to Manager2
        let message1 = format!("Test message {} from 1 to 2", i).into_bytes();
        let encrypted1 = manager1.encrypt_message(addr2, &message1)
            .expect("Failed to encrypt message from 1 to 2");
        let decrypted1 = manager2.decrypt_message(addr1, &encrypted1)
            .expect("Failed to decrypt message from 1 to 2");
        assert_eq!(message1, decrypted1);
        
        // Manager2 to Manager1
        let message2 = format!("Test message {} from 2 to 1", i).into_bytes();
        let encrypted2 = manager2.encrypt_message(addr1, &message2)
            .expect("Failed to encrypt message from 2 to 1");
        let decrypted2 = manager1.decrypt_message(addr2, &encrypted2)
            .expect("Failed to decrypt message from 2 to 1");
        assert_eq!(message2, decrypted2);
    }
}

#[test]
fn test_channel_rekeying() {
    // Create two secure channel managers
    let manager1 = SecureChannelManager::new();
    let manager2 = SecureChannelManager::new();
    
    // Get their public keys
    let pubkey1 = manager1.get_public_key();
    let pubkey2 = manager2.get_public_key();
    
    // Create test addresses
    let addr1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8001);
    let addr2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8002);
    
    // Establish secure channels
    manager1.establish_channel(&pubkey2, addr2).expect("Failed to establish channel 1->2");
    manager2.establish_channel(&pubkey1, addr1).expect("Failed to establish channel 2->1");
    
    // Send many messages to trigger rekeying (happens every 100 messages)
    for i in 0..101 {
        let message = format!("Test message {}", i).into_bytes();
        let encrypted = manager1.encrypt_message(addr2, &message)
            .expect("Failed to encrypt message");
        let decrypted = manager2.decrypt_message(addr1, &encrypted)
            .expect("Failed to decrypt message");
        
        // Verify messages still decrypt correctly even after rekeying
        assert_eq!(message, decrypted, "Message {} failed to decrypt correctly", i);
    }
    
    // Send additional messages to verify channel still works after rekeying
    let final_message = b"After rekeying test message";
    let encrypted = manager1.encrypt_message(addr2, final_message)
        .expect("Failed to encrypt message after rekeying");
    let decrypted = manager2.decrypt_message(addr1, &encrypted)
        .expect("Failed to decrypt message after rekeying");
    
    assert_eq!(final_message.to_vec(), decrypted, "Post-rekeying message failed");
}

#[test]
fn test_channel_close() {
    // Create two secure channel managers
    let manager1 = SecureChannelManager::new();
    let manager2 = SecureChannelManager::new();
    
    // Get their public keys
    let pubkey1 = manager1.get_public_key();
    let pubkey2 = manager2.get_public_key();
    
    // Create test addresses
    let addr1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8001);
    let addr2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8002);
    
    // Establish secure channels
    manager1.establish_channel(&pubkey2, addr2).expect("Failed to establish channel 1->2");
    manager2.establish_channel(&pubkey1, addr1).expect("Failed to establish channel 2->1");
    
    // Exchange a message to verify the channel is working
    let test_message = b"Test message before channel close";
    let encrypted = manager1.encrypt_message(addr2, test_message)
        .expect("Failed to encrypt message");
    let decrypted = manager2.decrypt_message(addr1, &encrypted)
        .expect("Failed to decrypt message");
    assert_eq!(test_message.to_vec(), decrypted);
    
    // Close the channel
    manager1.close_channel(addr2).expect("Failed to close channel 1->2");
    
    // Attempt to use the closed channel
    let post_close_message = b"Test message after channel close";
    let encrypt_result = manager1.encrypt_message(addr2, post_close_message);
    
    // Should fail because the channel is closed
    assert!(encrypt_result.is_err(), "Channel should be closed");
}

#[test]
fn test_random_data_encryption() {
    let manager1 = SecureChannelManager::new();
    let manager2 = SecureChannelManager::new();
    
    let pubkey1 = manager1.get_public_key();
    let pubkey2 = manager2.get_public_key();
    
    let addr1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8001);
    let addr2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8002);
    
    manager1.establish_channel(&pubkey2, addr2).expect("Failed to establish channel 1->2");
    manager2.establish_channel(&pubkey1, addr1).expect("Failed to establish channel 2->1");
    
    let mut rng = OsRng;
    
    // Test with random sized messages
    for _ in 0..10 {
        // Generate a random message with random length between 1 and 1000 bytes
        let length = rng.gen_range(1..1000);
        let mut random_message = vec![0u8; length];
        rng.fill(&mut random_message[..]);
        
        // Encrypt and decrypt
        let encrypted = manager1.encrypt_message(addr2, &random_message)
            .expect("Failed to encrypt random message");
        let decrypted = manager2.decrypt_message(addr1, &encrypted)
            .expect("Failed to decrypt random message");
        
        assert_eq!(random_message, decrypted, "Random message failed to encrypt/decrypt correctly");
    }
}

#[test]
fn test_message_uniqueness() {
    let manager1 = SecureChannelManager::new();
    let manager2 = SecureChannelManager::new();
    
    let pubkey1 = manager1.get_public_key();
    let pubkey2 = manager2.get_public_key();
    
    let addr1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8001);
    let addr2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8002);
    
    manager1.establish_channel(&pubkey2, addr2).expect("Failed to establish channel 1->2");
    manager2.establish_channel(&pubkey1, addr1).expect("Failed to establish channel 2->1");
    
    // Encrypt the same message multiple times
    let message = b"Test message for uniqueness";
    let mut encrypted_messages = HashSet::new();
    
    for _ in 0..10 {
        let encrypted = manager1.encrypt_message(addr2, message)
            .expect("Failed to encrypt message");
        
        // Convert to a form that can be used in a HashSet
        let serialized = bincode::serialize(&encrypted).expect("Failed to serialize");
        
        // Each encrypted message should be unique even though the plaintext is the same
        assert!(encrypted_messages.insert(serialized), "Encrypted messages should be unique");
    }
}
