using API.FurnitureStore.Data;
using Microsoft.AspNetCore.Mvc;
using API.FurnitureStore.Shared;
using Microsoft.EntityFrameworkCore;

namespace API.FurnitureStore.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class OrdersController : ControllerBase
    {
        private readonly APIFurnitureContext _context;

        public OrdersController(APIFurnitureContext context)
        {
            _context = context;
        }

        [HttpGet]
        public async Task<IEnumerable<Order>> GetOrders()
        {
            return await _context.Orders.Include(o => o.OrderDetails).ToListAsync();
        }

        [HttpGet("{id}")]
        public async Task<IActionResult> GetOrder(int id)
        {
            Order? order = await _context.Orders.Include(o => o.OrderDetails).FirstOrDefaultAsync(o => o.Id == id);
            if (order == null)
                return NotFound();

            return Ok(order);
        }

        [HttpPost]
        public async Task<IActionResult> CreateOrder(Order order)
        {
            if (order.OrderDetails == null)
                return BadRequest("Order should have at least one details");

            await _context.AddAsync(order);
            await _context.AddRangeAsync(order.OrderDetails);
            await _context.SaveChangesAsync();

            return CreatedAtAction("CreateOrder", order.Id, order);
        }

        [HttpPut("{id}")]
        public async Task<IActionResult> UpdateOrder(int id, Order order)
        {
            if (order == null || order.OrderDetails == null || order.Id != id || order.Id <= 0)
                return BadRequest();

            Order? existengOrder = await _context.Orders.Include(o => o.OrderDetails).FirstOrDefaultAsync(o => o.Id == id);
            if (existengOrder == null)
                return NotFound();

            existengOrder.OrderNumber = order.OrderNumber;
            existengOrder.OrderDate = order.OrderDate;
            existengOrder.DeliveryDate = order.DeliveryDate;
            existengOrder.ClienteId = order.ClienteId;

            if (existengOrder.OrderDetails != null)
                _context.OrderDetails.RemoveRange(existengOrder.OrderDetails);
            

            _context.Orders.Update(existengOrder);
            _context.OrderDetails.AddRange(order.OrderDetails);
            await _context.SaveChangesAsync();

            return NoContent();
        }

        [HttpDelete("{id}")]
        public async Task<IActionResult> DeleteOrder(int id)
        {
            Order? order = await _context.Orders.Include(o => o.OrderDetails).FirstOrDefaultAsync(o => o.Id == id);
            if (order == null) return NotFound();

            _context.OrderDetails.RemoveRange(order.OrderDetails);
            _context.Orders.Remove(order);
            await _context.SaveChangesAsync();

            return NoContent();
        }
    }
}
