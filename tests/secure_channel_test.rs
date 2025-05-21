use pali_coin::secure_channel::SecureChannelManager;
use std::net::{SocketAddr, IpAddr, Ipv4Addr};

#[test]
fn test_secure_channel() {
    // Create two secure channel managers (one for each peer)
    let manager1 = SecureChannelManager::new();
    let manager2 = SecureChannelManager::new();
    
    // Get public keys
    let pubkey1 = manager1.get_public_key();
    let pubkey2 = manager2.get_public_key();
    
    // Create socket addresses
    let addr1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8333);
    let addr2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8334);
    
    // Establish channels
    manager1.establish_channel(&pubkey2, addr2).unwrap();
    manager2.establish_channel(&pubkey1, addr1).unwrap();
    
    // Test message encryption and decryption
    let message = b"This is a secure test message";
    
    // Encrypt message from peer 1 to peer 2
    let encrypted = manager1.encrypt_message(addr2, message).unwrap();
    
    // Decrypt on peer 2
    let decrypted = manager2.decrypt_message(addr1, &encrypted).unwrap();
    
    assert_eq!(message.to_vec(), decrypted);
    
    // Test replay attack prevention
    let result = manager2.decrypt_message(addr1, &encrypted);
    assert!(result.is_err(), "Replay attack should be detected");
}
