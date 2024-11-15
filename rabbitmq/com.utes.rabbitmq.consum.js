/* link to code: https://geshan.com.np/blog/2021/07/rabbitmq-docker-nodejs/
 * command to start rabbitmq server: docker run -p 15672:15672 -p 5672:5672 --name rabbit-image-name rabbitmq:management
 * FAQ: What is the max size of one single message in RabbitMQ?
 * While the theoretical message size limit in RabbitMQ is 2GB up to 3.7.0, we don't recommend sending messages larger than 128MB, which is also the new max size limit in 3.8.0 and onward. Large messages are especially problematic when using mirrored queues in HA clusters and can cause memory and performance issues.
 * References:
 * https://github.com/rabbitmq/rabbitmq-server/issues/147#issuecomment-470882099
 * https://github.com/rabbitmq/rabbitmq-common/pull/289.
 *
 * 
 * 
 * 
 * 
 * 
 */



const amqplib = require('amqplib');
const amqpUrl = process.env.AMQP_URL || 'amqp://ajeetphadnis:Ajeet786@localhost:5672';


/**
 * Function: processMessages
 * @param {*} msg 
 */
async function processMessage(msg) {
  console.log(msg.content.toString(), 'Call email API here');
  //call your email service here to send the email
}

/**
 * Function: sync
 * This function connects app to rabbitmq and creates a queue
 * with name privided by the user
 */

(async () => {
    const connection = await amqplib.connect(amqpUrl, "heartbeat=60");
    const channel = await connection.createChannel();
    channel.prefetch(10);
    const queue = 'user.sign_up_email';
    process.once('SIGINT', async () => { 
      console.log('got sigint, closing connection');
      await channel.close();
      await connection.close(); 
      process.exit(0);
    });

    await channel.assertQueue(queue, {durable: true});
    await channel.consume(queue, async (msg) => {
      console.log('processing messages');      
      await processMessage(msg);
      await channel.ack(msg);
    }, 
    {
      noAck: false,
      consumerTag: 'email_consumer'
    });
    console.log(" [*] Waiting for messages. To exit press CTRL+C");
})();