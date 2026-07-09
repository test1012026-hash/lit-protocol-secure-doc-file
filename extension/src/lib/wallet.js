import { JsonRpcProvider, Wallet, ethers, formatEther } from "ethers";
import { POLYGON_API_KEY, POLYGON_PRIVATE_ADDRESS, POLYGON_SENDER_PRIVATE_KEY } from "./config";

const provider = new JsonRpcProvider(
  `https://polygon-amoy.g.alchemy.com/v2/${POLYGON_API_KEY}`,
);

const senderWallet = new Wallet(
  POLYGON_SENDER_PRIVATE_KEY,
  provider,
);

export async function transferFund(amount = "1") {
  try {
    console.log("Sender Address:", senderWallet.address);

    const balance = await provider.getBalance(senderWallet.address);
    console.log("Sender Balance:", formatEther(balance), "POL");

    const amountWei = ethers.parseEther(amount);

    if (balance < amountWei) {
      throw new Error(
        `Insufficient balance. Have ${formatEther(balance)} POL, need ${amount} POL.`,
      );
    }

    const tx = await senderWallet.sendTransaction({
      to: POLYGON_PRIVATE_ADDRESS,
      value: amountWei,
    });

    console.log("Transaction Submitted");
    console.log("Hash:", tx.hash);

    const receipt = await tx.wait();

    console.log("Transaction Confirmed in block:", receipt.blockNumber);

    const newBalance = await provider.getBalance(POLYGON_PRIVATE_ADDRESS);
    console.log("Recipient new balance:", formatEther(newBalance), "POL");

    return receipt;
  } catch (error) {
    console.error("Transfer failed:", error.message);
    throw error;
  }
}
